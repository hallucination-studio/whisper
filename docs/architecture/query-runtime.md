# Query delivery runtime architecture

- Status: accepted architecture
- Scope: query read ownership, command write ownership, runtime composition
  seams, and backpressure invariants
- Normative behavior:
  [`../specs/api-ui-v1.md`](../specs/api-ui-v1.md)

This page records architecture that cannot be recovered merely by listing
source files. It does not define routes, DTO fields, status codes, UI content,
implementation status, or acceptance results.

## Ownership

The ingest module is the only owner of mutable Timeline, baseline estimator,
and current world state. It owns the database writer and publishes committed
derived projections in the same transactions that advance processing state.

The query projection module owns bounded, indexed reads over immutable committed
projections. Its interface accepts domain selectors and query budgets and
returns typed views plus provenance. It has no interface to Engine working
state and no authority to reinterpret raw session records.

The HTTP/WebSocket adapter owns transport parsing, serialization, connection
lifecycle, and per-client delivery buffers. It delegates semantic reads to the
query projection module and submits state-changing commands through the one
ordered command seam. It does not own world or baseline state.

The diagnostic UI is a consumer adapter. HTTP is its semantic state source;
WebSocket delivery only invalidates that state.

## Composition seams

```text
                         ordered command
HTTP adapter ------------------------------------+
    |                                             |
    | bounded query                              v
    v                                     single ingest owner
query projection module                    Engine + DB writer
    |                                             |
    | read-only committed snapshot                | committed projection
    v                                             v
             one SQLite database in WAL mode
                              |
                              | small invalidation after commit
                              v
                       WebSocket adapter
                              |
                              v
                        diagnostic UI
```

Synchronous SQLite reads execute away from ingest and asynchronous network
execution. Read concurrency is explicitly bounded; adding a connection pool,
repository/provider interface, query actor, second database, or state cache is
not an architectural seam in v1.

The read interface is concrete because v1 has one projection implementation.
The command seam exists because HTTP and ingest have different ownership and
ordering requirements. The browser seam exists because reconnect and delivery
loss make HTTP resynchronization a real second interaction mode.

## Invariants

- A read observes one committed SQLite snapshot. It cannot combine working
  Engine memory with committed rows.
- Only the ingest owner mutates semantic state. HTTP submits commands but does
  not directly mutate baselines or hold mutable Engine access.
- A live invalidation is published only after the corresponding projection
  commit. Failed or rolled-back projection work emits no notification.
- Query work, a full command queue, a slow WebSocket client, or browser failure
  cannot apply backpressure to ingest.
- Every socket, command, read, and per-client notification queue has a finite
  configured bound. Exhaustion is observable at its owning seam.
- WebSocket delivery state is disposable and non-semantic. Recovery crosses
  the HTTP read seam and returns to committed SQLite projections.
These invariants constrain implementations while leaving transport behavior to
the v1 specification and implementation facts to code and behavior tests.
