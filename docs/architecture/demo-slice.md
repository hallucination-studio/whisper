# Demo Slice architecture

- Status: accepted architecture
- Scope: bounded Demo Store, capture, query, delivery, and browser seams
- Normative behavior: [Demo Slice v1](../specs/demo-slice-v1.md)

This document owns the non-discoverable responsibility boundaries and
invariants for the bounded Demo Slice. It does not define exact schema, API
bytes, status, or executed evidence.

## Ownership

The application owns the three operator intents: configuration validation,
Demo Store initialization, and running the Host. Initialization is the only
creating intent. The running intent owns one complete lifetime from
non-creating Store validation through Capture Session creation, capture,
delivery shutdown, and connection close.

The shared `HostLifecycle` boundary owns Managed store root validation and the
retained cooperative lease for both creating and running intents. The
managed-store module owns private staged initialization, atomic no-replace
publication, and non-creating opens. Demo-specific schema validation and
Capture Session behavior remain behind that shared boundary.

The capture adapter owns UDP receipt, receive timestamps, exact HeaderRoute
selection, authentication, and in-memory rate admission. It creates a pure
bounded wire candidate and has no Store, replay, capability, Profile, or query
authority.

One bounded queue separates asynchronous UDP receipt from one blocking writer.
The writer alone owns the SQLite writer connection, replay mutation, committed
capability resolution, packet ordering, native-coordinate observation
construction, Capture Session cursor, and Store watermark. Queue overflow is a
counted reject and cannot block the socket or become a partial Store mutation.

SQLite is the only persistent and query authority. A transaction-local derived
map may simplify one candidate or read, but it ends with that transaction and
cannot become a process-lifetime capability or Profile catalog.

The query module owns bounded reads of committed topology and native-coordinate
CSI. Each read returns a complete typed body and receipt from one SQLite
snapshot. It cannot read current configuration or writer memory.

The HTTP/WebSocket adapter owns transport, strict JSON serialization, upgrade
lifecycle, and bounded per-client invalidation queues. HTTP is the state path;
WebSocket messages carry only Store watermark invalidation.

The browser is a read-only consumer. It owns selection and rendering state,
receipt validation, WebSocket resynchronization, and the polling fallback. It
does not own sensing state and exposes no command seam.

## Composition seams

```text
ESP32-S3 datagram
  -> UDP capture/auth/rate adapter
  -> pure WireCandidate
  -> bounded writer queue
  -> one blocking SQLite writer
       -> replay + packet + optional capability/CSI + cursor + watermark
  -> postcommit watermark notification

SQLite committed snapshot
  -> QueryStore
  -> HTTP topology/signals + same-snapshot receipt
  -> read-only browser

postcommit watermark
  -> bounded WebSocket invalidation
  -> canonical HTTP resync
```

The writer queue is an execution boundary, not an authority boundary. Only a
successful SQLite commit authorizes publication. The WebSocket queue may lose
or coalesce invalidations because HTTP receipt comparison restores correctness.

Synchronous SQLite work runs away from async socket and transport execution.
The Demo introduces no connection pool, database actor, ORM, repository/provider
interface, second fact store, or general migration framework.

## Invariants

- One physical board is acceptance scope only; every collection, selector,
  ownership rule, and Store relation remains dynamic in configured count.
- Store initialization and running are separate intents. Running cannot create,
  migrate, repair, reset, or replace a Store.
- Initialization and running each retain the Managed store root lease until all
  SQLite connections for that intent are closed. No second cooperative writer
  lifecycle can enter the same root concurrently.
- Every running Host creates one new non-semantic Capture Session. Host restart
  never continues it, while Store-scoped replay and capability authority remain
  durable.
- Server transport is loopback-only; UDP capture remains board-reachable.
- Candidate decoding is pure. No parse result, memory catalog, or notification
  can authorize replay, capability, Profile membership, visibility, or query.
- One sequential writer owns all mutation. Each replay-admitted packet has one
  complete SQLite transaction and one Store watermark advance.
- Replay mutation, exact packet retention, optional capability or CSI, Capture
  Session cursor, and Store watermark share one rollback boundary.
- A committed capability must precede CSI that uses it. Later arrival cannot
  reinterpret an earlier packet.
- Query state comes only from committed SQLite rows. Body and receipt share one
  read snapshot.
- WebSocket is invalidation only. Polling is an explicit, correctly labelled
  fallback and cannot be represented as WebSocket-live state.
- Memory is disposable. Rollback or restart cannot leave authoritative
  capability, Profile, cursor, or query state in memory.
- The Demo Slice has no Timeline, estimator, Engine, World, semantic recovery,
  retention, handoff, or formal evidence-classification owner.

The per-serve Capture Session rationale is recorded in
[ADR 0016](../adr/0016-new-capture-session-per-serve.md). The single atomic
admitted-packet transaction rationale is recorded in
[ADR 0017](../adr/0017-atomic-demo-ingest.md).
