# Temporal world runtime architecture

This document owns the non-discoverable responsibility allocation, dependency
direction, seams, and invariants for Whisper's temporal world runtime. Exact
behavior lives only in the
[temporal world v1 specification](../specs/temporal-world-v1.md), evaluation and
leakage behavior in [evaluation v1](../specs/evaluation-v1.md), and maturity in
the [world/runtime evidence index](../evidence/world-runtime.md).

## Responsibilities

Timeline owns source-sequence classification, stream-instance lifecycle,
watermarks, fixed windows, missing spans, and canonical digest state. It
does not own signal transformation, baseline state, persistence, or scheduling
clocks.

Conditioning owns the pure conversion from one aligned dynamic-coordinate
window to one aggregate conditioned link window per computed Link/Profile key,
including empty-contributor output, auditable per-coordinate values, and
ordered stream-segment provenance. It does not own window closure, baseline
lifecycle, world aggregation, or I/O.

The statistical estimator owns evolution of the canonical complete baseline
state, its lifecycle and update decisions, link/profile evidence, physical-link
reduction, and conservative space aggregation. It consumes conditioned values
rather than wire or raw-window values.

Engine owns Timeline, conditioning, estimator mutation, and current world
state behind one synchronous semantic interface. It is the only module that can
produce a world transition.

The application owns runtime composition: `CaptureRun` orders socket and command
input, owns the sole persistence writer connection, coordinates decoding,
requests Engine semantic transitions, and sequences publication, shutdown, and
bounded delivery. Engine alone owns its mutable Timeline, estimator, and World
state. The application persists Engine's concrete transition; it does not
reconstruct or duplicate temporal, baseline, evidence, or world computations.

Durability owns committed state and projections at the Engine publication
seam. Read/query modules consume committed immutable projections. They do not
read or mutate Engine working state.

## Dependency direction

```text
typed domain values + validated semantic configuration
    -> Timeline
    -> conditioning
    -> statistical estimator
    -> Engine
    -> application composition and durability publication
    -> committed read projections
```

Timeline, conditioning, and the estimator are synchronous and free of network,
filesystem, wall-clock, and global-configuration access. The estimator has no
dependency on wire, session transport, durability, application, delivery, or
query modules. Engine has no dependency on runtime delivery or query concerns.

Concrete types cross these seams. Internal state codecs remain owned by the
module whose invariants they encode. Durability stores those strong values and
does not introduce parallel state DTOs or generic value interfaces.

## Seams

```text
durably admitted typed observation or ordered command
    -> Timeline input seam
    -> AlignedWindow seam
    -> ordered ConditionedLinkWindow set seam
    -> estimator evidence/state seam
    -> EngineTransition with complete WindowProjection seam
    -> atomic durability/publication seam
    -> immutable read and notification seam
```

The Timeline input seam separates authenticated dynamic facts from temporal
classification. Source sequence is classified before profile partition, so
profile layout does not redefine source loss.

The AlignedWindow seam separates temporal closure from signal transformation.
It retains actual time, profile, gaps, missing spans, and dynamic coordinates;
conditioning cannot repair or reinterpret temporal facts.

The ConditionedLinkWindow set seam is the estimator's only signal input. Its
keys equal the strict union of that window's observation or missing-span
contributor keys and Engine's current baseline-state keys. The set may be empty;
each present key advances exactly once, and a key is not invented when neither
source supplies it. This prevents raw windows, per-stream estimator updates,
fixed tensors, and ad hoc transformations from becoming alternate baseline
paths.

The EngineTransition seam is the complete mutation result. Engine owns each
WindowProjection as one snapshot plus the complete ordered aggregate-evidence
set whose keys equal that snapshot's computed link keys. The application
commits the exact projection and canonical Timeline digest without regrouping,
sorting, or recomputing them, which keeps state calculation on one side and
atomic publication on the other.

The durable publication seam separates working state from observable state.
Readers and notifications see only a committed projection identity created by
the same transition transaction. Recovery and replay construct a fresh Engine
and Timeline and use the ordinary semantic interface. Exact recovery cursor,
row-comparison, digest-tripwire, fail-closed, and no-repair behavior is owned by
the [host persistence v1 specification](../specs/persistence-v1.md). Isolated
replay enters through the same ordered semantic input seam and stops before
durability or delivery effects.

## Single-writer ownership

One ingest owner calls Engine in session record order and exclusively owns its
mutable Timeline, baseline, and current snapshot state. Engine is not placed
behind a global write lock, shared with HTTP handlers, or split into independent
actors. Commands cross a bounded queue and join the same durable total order as
observations and advances.

This ownership is distinct from synchronous durable I/O. The application may
schedule I/O away from async executors, while preserving the single semantic
writer and atomic transition order. Read concurrency occurs only against
committed immutable projections.

The rationale is recorded in
[ADR 0002](../adr/0002-engine-single-writer.md).

## Invariants

- There is one semantic mutation path from ordered input to world state and one
  global snapshot per closed window.
- Every clock input to Timeline and Engine is explicit and replayable.
- Source, stream instance, profile, link, and baseline compatibility identities
  remain distinct; profile changes never merge estimator state.
- Every key in the per-window contributor/baseline union produces exactly one
  conditioned aggregate and one estimator step. An empty union produces none.
  Stream-segment contributors are ordered provenance; conditioning explicitly
  sorts matching observations by unique session-global record sequence before
  each fold and does not depend on AlignedWindow collection order. Slopes never
  cross segment boundaries, and contributor count never multiplies quality or
  exposure.
- Missing and Unknown remain typed domain outcomes. Invalid input or broken
  invariants remain classified errors rather than fabricated observations.
- Estimator evidence is calculated from pre-update state and travels with the
  exact resulting state in one Engine transition. Each WindowProjection owns
  exactly one evidence item per snapshot Link/Profile key.
- Engine alone owns the semantic completeness of each WindowProjection,
  including the contributor/baseline union and omitted-key decision.
- The application publishes no mirror, projection, or notification before the
  complete corresponding transition commits.
- A failed raw commit does not call Engine. A failed semantic commit exposes no
  partial transition and stops further capture before publication.
- Live capture and recovery preserve one Engine transition per ordered semantic
  input. Authenticated decode rejects do not enter Engine; their private
  record-processing transition and durability behavior is owned by the
  [host persistence architecture](host-persistence.md). The application cannot
  aggregate, reorder, drop, split, or recompute Engine transitions before
  durability.
- Physical-link and space reductions are stable-order and conservative.
  Multiple profiles of one physical link never inflate coverage.
- Complete baseline state crosses explicit finish, rotation, recovery, and
  replay; in-memory state is not resume authority.
- A compatible Host restart rebuilds the same active semantic state and cannot
  reset Timeline windows, stream instances, estimator arming, or World identity.
  Only explicit finish or limit rotation creates a session handoff.
- SQLite ordered facts, not a serialized Timeline value, are recovery authority.
  The [host persistence v1 specification](../specs/persistence-v1.md) owns exact
  recovery behavior.
- Runtime delivery, query order, processing duration, and host wall time never
  enter semantic snapshot identity.
