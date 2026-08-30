# Demo Slice architecture

- Status: accepted architecture
- Scope: bounded Store, capture, query, delivery, and browser seams
- Normative behavior: [Demo Slice v1](../specs/demo-slice-v1.md)

This document owns the non-discoverable responsibility boundaries and
invariants for the bounded Demo Slice. It does not define exact schema, API
bytes, status, or executed evidence.

## Ownership

The application owns the three operator intents: configuration validation,
Store initialization, and running the Host. Initialization is the only
creating intent. The running intent owns one complete lifetime from
non-creating Store validation through Capture Session creation, capture,
delivery shutdown, and connection close.

`HostRuntime` is the sole public running-lifecycle module. Its interface owns
startup, stop observation, shutdown, and immutable bound-address/session facts.
Callers never own capture, HTTP, WebSocket, query, writer, socket, task, or
lease handles. Dropping `HostRuntime` or cancelling its shutdown future only
requests stop; neither action owns or cancels cleanup.

An independent `HostSupervisor` thread owns cleanup from successful startup
until final completion. It retains the last `CaptureRuntime` and `QueryStore`
owners, arbitrates the first fatal error, bounds transport shutdown, performs
blocking teardown, and releases the lifecycle lease. Tokio workers may request
stop and report task results, but never close the final SQLite connection or
join the writer thread.

The shared `HostLifecycle` boundary owns Managed store root validation and the
retained cooperative lease for both creating and running intents. The
managed-store module owns private staged initialization, atomic no-replace
publication, and non-creating opens. Bounded-path schema validation and
Capture Session behavior remain behind that shared boundary.

The `CaptureRuntime` module owns UDP receipt, receive timestamps, exact
HeaderRoute selection, authentication, and in-memory rate admission. It creates
a pure bounded wire candidate and has no Store, replay, capability, Profile, or
query authority.

Exactly one bounded candidate queue separates asynchronous UDP receipt from one
blocking writer.
The writer alone owns the SQLite writer connection, replay mutation, committed
capability resolution, packet ordering, native-coordinate observation
construction, Capture Session cursor, and Store watermark. Queue overflow is a
counted reject and cannot block the socket or become a partial Store mutation.
Lifecycle control and postcommit notification channels never carry candidates
and are not fact or ordering authorities.

SQLite is the only persistent and query authority. A transaction-local derived
map may simplify one candidate or read, but it ends with that transaction and
cannot become a process-lifetime capability or Profile catalog.

The query module owns bounded reads of committed topology and native-coordinate
CSI. Each read returns a complete typed body and receipt from one SQLite
snapshot. It cannot read current configuration or writer memory.

The HTTP module owns loopback listener admission, strict JSON serialization,
ordinary-connection tracking, and bounded shutdown. Its tracked stream adapter
retains a shutdown handle for every accepted TCP connection. The WebSocket
module owns upgrade lifecycle and bounded per-client invalidation queues. HTTP
is the state path; WebSocket messages carry only Store watermark invalidation.

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
The final pinned `QueryStore` connection closes and the writer thread joins on
the independent supervisor thread. The supervisor-owned executor is not
destroyed until its blocking capture and query jobs complete, so a cancelled
transport task cannot leave an unowned lease.
The delivery path introduces no connection pool, database actor, ORM,
repository/provider interface, second fact store, or general migration
framework.

## Fatal stop and teardown

Every capture, writer, query, socket, HTTP, WebSocket, or supervised-task panic
or fatal result records one stable primary failure and immediately requests a
Host-wide stop. Errors caused by that stop do not replace the primary failure.
The primary failure is returned only after complete cleanup; a teardown failure
becomes primary only when no earlier fatal failure exists.

Shutdown first stops UDP receipt, HTTP accepts, WebSocket delivery, and new
query jobs. HTTP receives a documented finite grace interval. At its expiry the
HTTP module shuts down every tracked TCP connection, including incomplete or
idle ordinary HTTP connections, interrupts the pinned SQLite reader, then waits
for Axum to join its connection tasks. Blocking query jobs report fatal or panic
directly to lifecycle control even if their HTTP waiter is cancelled. The
supervisor next stops and joins the sole writer, drains the executor's blocking
jobs, closes the pinned query connection, and finally releases the Managed
store root lease. Cancellation of a shutdown future or loss of the public
handle cannot shorten or reorder this sequence.

Socket failures retain their socket role, operation, configured or bound
address, and operating-system source. Network-role admission remains a distinct
pre-Store validation result; a bind failure may additionally classify an
address as non-local without discarding its socket context.

## Invariants

- One physical board is acceptance scope only; every collection, selector,
  ownership rule, and Store relation remains dynamic in configured count.
- Store initialization and running are separate intents. Running cannot create,
  migrate, repair, reset, or replace a Store.
- Initialization and running each retain the Managed store root lease until all
  SQLite connections for that intent are closed. No second cooperative writer
  lifecycle can enter the same root concurrently.
- `HostSupervisor`, not `HostRuntime` or its shutdown future, owns final cleanup
  and publishes completion only after the lease is released.
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
- A slow, idle, or incomplete ordinary HTTP connection cannot extend Host
  shutdown beyond the transport grace and forced-close sequence.
- Memory is disposable. Rollback or restart cannot leave authoritative
  capability, Profile, cursor, or query state in memory.
- The Demo Slice has no Timeline, estimator, Engine, World, semantic recovery,
  retention, handoff, or formal evidence-classification owner.

The per-serve Capture Session rationale is recorded in
[ADR 0016](../adr/0016-new-capture-session-per-serve.md). The single atomic
admitted-packet transaction rationale is recorded in
[ADR 0017](../adr/0017-atomic-capture-ingest.md).
