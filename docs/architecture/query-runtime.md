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

`CaptureRun` owns ingest order and the sole synchronous database writer
connection. Engine alone owns the mutable Timeline, estimator, and current
World state. The persistence module owns committed rows and creates their
projection commit identities. No one of these owners exposes its mutation
interface to query or delivery.

The query projection module owns bounded, indexed reads over immutable committed
projections. Store topology comes from the immutable provisioned topology
manifest; visible sessions and facts come only through persistence-owned
visibility views cut at the committed processing cursor. Its interface accepts
domain selectors and query budgets and returns typed views plus provenance and
the Projection watermark observed in the same read snapshot. It has no
interface to Engine working state, current TOML, base fact tables, or authority
to reinterpret raw session records. This is the ordinary HTTP/query read seam;
the lifecycle-owned sealed-session corpus-export snapshot and faithful replay
iterator are separate persistence seams.

The HTTP/WebSocket adapter owns transport parsing, serialization, connection
lifecycle, and per-client delivery buffers. It delegates semantic reads to the
query projection module and submits state-changing commands through the one
ordered command seam. It does not own world or baseline state.

The diagnostic UI is a consumer adapter. HTTP is its semantic state source;
WebSocket delivery only invalidates that state and carries the Projection
watermark that the next HTTP read must reach. Sequence zero is a valid handshake
watermark but is not a Committed projection identity.

## Composition seams

```text
                         ordered command
HTTP adapter ------------------------------------+
    |                                             |
    | bounded query                              v
    v                                         CaptureRun
query projection module                 ingest order + DB writer
    |                                             |
    |                                      exclusive Engine
    | read-only committed snapshot       Timeline + estimator + World
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
- Transaction A cannot affect a query: readers cannot access a session before
  its first transaction B or a record beyond that session's committed processing
  cursor, and Store topology never comes from mutable runtime configuration.
  Committed observation and baseline projections supply only dynamic Profile
  membership, including first-B baseline publication after a decode reject.
- `CaptureRun` alone orders ingest and owns the writer connection; Engine alone
  mutates Timeline, estimator, and World. HTTP submits commands but does not
  directly mutate baselines or hold mutable Engine access.
- A live invalidation is published only after the corresponding projection
  commit and binds that commit identity. Failed or rolled-back projection work
  emits no notification.
- A new WebSocket connection always receives the current zero-capable
  Projection watermark. Only transaction B or retention can produce and publish
  a nonzero Committed projection identity.
- Persistence advances the global query-visible Store watermark in the same
  transaction as a retention deletion and hands only the committed identity to
  delivery. The API/UI specification alone owns the invalidation name and
  publication behavior. No query-visible mutation reuses a prior identity.
- Query work, a full command queue, a slow WebSocket client, or browser failure
  cannot apply backpressure to ingest.
- Every socket, command, read, and per-client notification queue has a finite
  configured bound. Exhaustion is observable at its owning seam.
- WebSocket delivery state is disposable and non-semantic. Recovery crosses
  the HTTP read seam and returns to committed SQLite projections at or beyond
  the reconnect watermark for the same Store ID.
- Query consistency is scoped to each SQLite read snapshot and receipt. The
  query runtime exposes no cross-request snapshot or multiversion-history seam;
  exact client resynchronization belongs to the API/UI specification.
These invariants constrain implementations while leaving transport behavior to
the v1 specification and implementation facts to code and behavior tests.
