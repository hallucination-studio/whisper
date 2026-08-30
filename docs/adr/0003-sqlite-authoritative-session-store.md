# ADR 0003: Use SQLite as the authoritative session store

Status: Accepted

Scope: this decision applies to the deferred Semantic Session Store. The Demo
also selects SQLite as its sole authority, but its smaller schema and atomic
ingest decision are owned by [ADR 0017](0017-atomic-capture-ingest.md) and
[Demo Slice v2](../specs/demo-slice-v2.md).

## Context

Whisper must atomically retain replay admission and exact encrypted packets,
then atomically retain semantic processing state and rebuildable projections.
Restart, recovery, query, retention, and faithful replay must agree on one
durable history.

The predecessor code has private CRC-framed session-file primitives, but the
executable has no production persistence workflow. Extending that format while
also adding a query database would create two stores whose authority and crash
boundaries could disagree. Keeping only a decoded or projected database would
lose the immutable admitted packet facts needed for faithful replay.

Changing the durable store later requires migrating session lifecycle,
admission, recovery, retention, query projections, and operational tooling as
one coherent history. The existing file primitives make the replacement
non-obvious: it trades a small append-file implementation for transactional
coordination and a larger embedded dependency.

## Decision

Use one embedded SQLite database as the sole authoritative host persistence
system for v1. It contains the admitted raw packet/control log and rebuildable
typed projections. The single ingest owner holds its writer connection; query
readers use the same database.

The session module continues to own strong manifest and record values and
their language-neutral codecs. SQLite remains an implementation detail of the
persistence module. V1 introduces no ORM, provider/repository trait, external
database service, generic migration framework, or second fact store.

The operative schema, transactions, recovery, retention, and replay behavior
are defined only by the
[host persistence v1 specification](../specs/persistence-v1.md).

## Consequences

- Replay admission and raw insertion can share one rollback boundary, while
  processing state and projections can share the later publication boundary.
- Raw facts and derived query state can be recovered and retained under one
  lifecycle without cross-store reconciliation.
- SQLite corruption or incompatible schema/state becomes a fail-closed startup
  condition; the application cannot fall back to predecessor session files.
- Existing CRC-framed file primitives are predecessor implementation facts,
  not a compatibility format or parallel runtime path.
- SQLite locking, WAL behavior, synchronous I/O isolation, schema integrity,
  and operational initialization become explicit engineering obligations.
- A future storage replacement must migrate one authoritative history and
  update this decision; adding a second adapter is not a v1 extension point.

## Alternatives considered

**Continue the CRC-framed session files.** This keeps a small append path but
does not provide one atomic home for replay admission, lifecycle, processing
cursor, complete baseline state, and query projections.

**Keep session files authoritative and add SQLite projections.** This was
rejected because recovery and retention would cross two durability systems and
operators could observe projections that disagree with the authoritative file
tail.

**Make SQLite projections authoritative and discard encrypted raw facts.**
This was rejected because decoded state cannot reproduce admission context or
faithful replay after decoder and algorithm changes.

**Introduce a storage-provider interface or external database.** This was
rejected because v1 has one concrete deployment need and one adapter. The
extra interface and operational surface would add no current variation or
leverage.
