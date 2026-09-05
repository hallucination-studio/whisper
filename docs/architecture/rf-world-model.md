# RF world-model architecture

This document owns the non-discoverable responsibilities, dependency direction,
seams, and invariants for Whisper's RF world model. Exact schemas, APIs,
algorithms, limits, timing, failure behavior, and acceptance criteria live in
the [RF world-model v1 specification](../specs/rf-world-model-v1.md).

The system is a hard replacement of the former Demo Slice and deferred
Semantic Program after native observation admission. The accepted rationale is
[ADR 0020](../adr/0020-rf-world-model-hard-rebuild.md). This page does not
define a migration or compatibility architecture.

## Authority and responsibilities

The firmware and native-ingress boundary owns acquisition of the deployed
ESP32-S3 observations. Firmware callback validation, native-frame v1 encoding,
authenticated UDP admission, replay admission, capability facts, receive
context, and lossless native CSI decoding remain the input path. This boundary
ends at an immutable source record. It has no scene, calibration, model,
person, world-state, or query authority.

Source adapters own the meaning and limitations of each native measurement
format. They preserve source instance and boot identity, transmitter, channel,
bandwidth, PHY, native LTF and path identity, native sample axes, raw IQ,
masks, RSSI, noise, rate/MCS, antenna fields, device ticks, receive facts, and
declared capability. An adapter may normalize an established meaning; it may
not infer an absent antenna, frequency coordinate, clock relation, phase
relation, or geometry.

Measurement assembly owns the bounded association of fragments that belong to
one RF measurement. It records membership, missing fragments, closure reason,
late arrivals, and association uncertainty. A closed assembly is immutable.
Time, phase, port, and geometry qualification own separate relations with
their errors, validity intervals, and epochs. No aggregate `calibrated` flag
may grant capabilities that were not individually established.

Fact persistence owns immutable source records, assembly decisions, relation
revisions, explicit gaps, and the references needed to reproduce model input.
It also owns bounded raw-segment retention. Deleting an eligible raw segment
records a retention hole; it does not delete the independently committed world
history. The Store has a new schema identity in an explicitly initialized new
directory. A runtime that encounters a former schema rejects it without
writing, importing, repairing, upgrading, or deleting it.

The spatial-artifact boundary owns versioned scene snapshots, device geometry,
scan coverage, calibration bundles, background-condition sets, supervision
segments, and their provenance and uncertainty. Phone capture imports artifacts
through this boundary. The phone is not an online world-state writer and is not
required after calibration.

The artifact registry owns immutable compatibility combinations of scene,
calibration, preprocessing, model, label semantics, and state format. It
qualifies candidate combinations through replay and shadow execution and
atomically activates one compatible combination for a state stream. Activation
never rewrites facts, prior results, or historical artifact versions.

Scene maintenance owns the competition among device-condition, human-state,
known-environment, and unexplained-structure candidates. It creates targeted
verification or phone-rescan work rather than changing formal background or
geometry from model output. Independently confirmed artifacts return through
the spatial-artifact and qualification boundaries; a structural rescan makes
room-wide RF compatibility pending until that combination is requalified.

The block scheduler owns causal, non-overlapping evidence blocks, explicit
missing-input steps, source age and eligibility, and the one-use assignment of
each source record. It produces an immutable input manifest that fixes every
fact, relation, artifact, mask, preprocessing version, causal cutoff, and input
digest used by one inference request. Tensor materialization occurs from that
manifest and cannot consult newer calibration or future data.

The model executor owns numerical feature extraction and evaluation of the
activated model. Its RF front end has the model-defined slow-response,
fast-change, and qualified array-path branches, followed by map-conditioned
fusion and one joint state potential. A Python/GPU worker may implement this
boundary, but its memory, caches, output arrival order, and process lifetime
have no authority. It receives immutable requests and returns bounded candidate
results and successor-state material only.

The state coordinator owns each room's single causal state stream. It validates
request identity, model run, epoch, predecessor checkpoint, cutoff, deadline,
shape, finiteness, and input digest. It advances the joint zero-to-two-person
state at most once per evidence block, persists explicit time-only advances,
serially arbitrates success against timeout or cancellation, and creates the
only publishable world result and successor checkpoint. A checkpoint is the
state stream's committed predecessor authority within an epoch; worker memory
and the former Timeline or Engine state are not.

World history owns immutable published state, validity and expiry events,
source summaries, artifact identities, observation gaps, association
ambiguity, and the bounded fields declared by the result-log contract. It is
independent of raw-segment retention. Prediction consumes an already committed
joint state and the physical dynamics defined by the active model combination.
Prediction cannot feed back into observation evidence or current state.

Query owns bounded reads over committed current world state, historical world
results, predictions, coverage, quality, freshness, artifact versions, and
retention gaps. Delivery transports those read models and committed
invalidation identities. Neither module reads worker memory, reconstructs
world state from raw facts on demand, mutates the state stream, or treats an
old HTTP/WebSocket receipt as authority.

Offline corpus, training, evaluation, and shadow execution consume sealed facts
and spatial artifacts under separate resource limits. They create candidate
artifacts and evaluation records, never production state. Historical evidence
packages remain immutable records of what the former system executed; they do
not qualify a new model or prove the new architecture's acceptance.

The Host application is the composition root and operational supervisor. It
owns resource budgets and priority across raw capture, persistence, online
inference, world publication, phone import/export, shadow inference, and
training. It does not own a second copy of state semantics. Formal state and
publication mutations pass through one Rust writer.

## Dependency direction

```text
existing firmware UDP
  -> authenticated native ingress
  -> immutable source facts
  -> source adapter + bounded measurement assembly
  -> explicit time / phase / port / geometry qualification
  -> causal evidence blocks + immutable input manifests

phone capture
  -> versioned scene / calibration / supervision artifacts
  -> artifact compatibility and activation

committed condition / residual candidates
  -> scene maintenance verification
  -> new candidate artifacts

input manifest + active compatible artifacts
  -> tensor materialization
  -> numerical model executor
  -> bounded candidate result + successor checkpoint
  -> single Rust state coordinator and writer
  -> committed current world + independent history + prediction
  -> bounded query and delivery
```

Dependencies flow from preserved facts and versioned artifacts toward derived
state. A derived result may name its inputs, but no reverse edge may turn a
prediction, query projection, inferred empty room, or worker cache into an RF
fact, calibration fact, background reference, or supervision label.

The native-ingress layer has no dependency on model code. Source adapters have
no dependency on scene interpretation. Numerical model code has no persistence
or publication capability. Query and delivery have no dependency on mutable
coordinator state. Offline training has no write path into the active artifact
set.

## Durability and commit seams

One Rust writer serializes all formal state changes. Its three durability seams
separate immutable acquisition, deterministic request construction, and
fallible model execution:

```text
A: ordered source facts + reconstruction provenance
B: deterministic projections + block cursor + input manifest + request identity
C: first qualified result + successor checkpoint + request terminal state
   + state-stream cursor + current world + history record + validity/expiry
   + publication watermark
```

Transaction A never grants semantic publication. Transaction B freezes what a
worker may process and makes retries content-identical. Transaction C is the
only world publication authority. A successful reply is acknowledged only
after C commits. Timeouts, cancellation, supersession, invalid output, and
model failure are durable terminal outcomes; retry races cannot replace an
already committed result.

Large tensor construction and numerical execution occur outside the writer,
but the writer rechecks identity, size, compatibility, deadline, epoch, and
predecessor before committing. Each online state stream has at most one
unresolved predecessor edge. Queue skipping or an unacceptable gap ends the
epoch instead of silently joining a discontinuous state chain.

Restart first finishes the bounded A-without-B tail, then closes unfinished
online work from the old epoch. It commits a new epoch and Unknown current
projection before reopening service and accumulating fresh causal context. A
self-contained checkpoint keeps ordinary in-epoch continuation independent of
deleted ancestor facts; it does not continue the old epoch across restart.
Replaying raw facts for analysis creates a distinct offline run and cannot
publish into the online stream.

## Resource and failure ownership

Raw receipt, durable fact commit, active online inference, state commit, and
publication have priority over corpus export, shadow work, and training. Every
queue, assembly, active source set, tensor, request, result, checkpoint, and
transaction has count and byte bounds. The writer uses bounded work units so a
single source or background task cannot starve state expiry or another source.

Native ingress continues recording qualified facts when a model worker fails.
An invalid, non-finite, oversized, late, or incompatible result becomes a model
failure and cannot update the world. Loss of persistence or writer authority
stops input admission and reports the resulting sensing gap without claiming a
committed world update. Loss of fresh qualified RF advances time and
uncertainty without manufacturing an observation.

## Hard replacement of former modules

The following names describe source areas in the repository at the rebuild
boundary. They do not prescribe the final file layout.

| Former area | RF world-model disposition |
| --- | --- |
| `application` and Host composition | Rewrite around source persistence, artifact activation, inference scheduling, state checkpoints, publication priority, and bounded shutdown. The former per-serve Capture Session lifecycle and old `CaptureRuntime` contract do not survive. |
| `store` | Rewrite the schema and typed store surface for segmented facts, assembly closure, artifact combinations, input manifests, requests, checkpoints, current world, and an independent result log. The new schema uses a separately initialized directory and rejects a former schema without writing it. Former session/projection/baseline/query tables, cursors, receipts, and retention semantics are not migrated. A managed root, cooperative lease, and qualified SQLite mechanics may be reused only as private implementation after satisfying the new contract. |
| `timeline` | Delete the former fixed-window, SessionTime, stream-segment, serialized-state, and replay model. Replace it with explicit clock relations, causal block scheduling, gaps, block cursors, and epoch-aware checkpoints. There is no Timeline codec compatibility. |
| `relationship` and old world domain | Delete the statistical baseline, Stable/Changing relationship estimator, baseline commands/handoffs, former `Engine`, and former `WorldSnapshot` semantics. Replace them with the three-branch RF observation model and the single joint causal world-state coordinator defined by the new specification. |
| `evidence` | Remove the former Program classification/claim graph from production authority and replace runtime provenance with immutable input manifests, source summaries, artifact qualifications, and evaluation records. Keep historical evidence documents, packages, and receipts intact as historical execution records. |
| `query`, HTTP, WebSocket, and browser DTOs | Rewrite against committed current world, history, prediction, coverage, freshness, and artifact identities. Former topology/signals endpoints, projection receipts, Store watermarks, and reconnect contract receive no compatibility layer. Transport mechanics may be reimplemented behind the new read model. |
| Firmware, native frame, wire admission, and native CSI observation | Preserve the deployed firmware behavior and UDP bytes as the external input contract. Preserve authenticated admission, capability and health facts, source/boot identity, raw IQ and masks, native LTF/path meaning, and `CsiPath::TxRx` semantics. Extend only downstream adapters and facts when the new specification requires information that is actually present. |

Code reuse is allowed only when an implementation unit already satisfies the
new contract without preserving an old semantic surface. Reusing code does not
make an old identity, schema, endpoint, state value, or recovery rule valid.

## Invariants

- Existing firmware datagrams remain accepted according to the native-frame v1
  contract; downstream code never asks firmware to invent unavailable RF
  information.
- Raw facts, scenes, calibration, model artifacts, checkpoints, current world,
  and historical results have distinct identities and version lifecycles.
- Unknown, missing, invalid, interpolated, and training-masked values remain
  distinct. Zero is a measurement value, not a missing-value encoding.
- Time alignment, phase coherence, port mapping, and geometry eligibility are
  separate scoped claims. Eligibility is checked per physical operator and per
  inference window.
- Each admitted source record enters at most one online evidence block. Cached
  history, model heads, predictions, and repeated delivery never count as new
  evidence.
- All outputs for presence, count, positions, and association derive from one
  joint state distribution and one causal predecessor. No independent vote or
  legacy relationship score may update the world alongside it.
- A state stream has one active model run, epoch, committed predecessor, and
  writer. Only transaction C advances its publishable state.
- Model workers are replaceable calculators. They cannot activate artifacts,
  select a predecessor, publish state, update background truth, or acknowledge
  their own result.
- Current state expires through a committed event even when no RF packet
  arrives. Old results and expiry events cannot cross an epoch to overwrite a
  newer state.
- World history survives eligible raw-fact deletion, while queries that require
  expired raw facts report that limitation explicitly.
- Phone observations may establish geometry and supervision during calibration;
  they are absent from ordinary online sensing unless a separately specified
  calibration operation is active.
- Training, replay, shadow inference, and prediction never feed their outputs
  into production observation evidence.
- Historical evidence is retained without granting the former program,
  classifications, schemas, or implementation any authority over the rebuilt
  system.
