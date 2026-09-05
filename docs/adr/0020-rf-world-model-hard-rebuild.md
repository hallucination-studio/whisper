---
status: accepted
---

# Hard-rebuild the Host around the RF world model

## Context

Whisper's former accepted architecture grew around a bounded native-CSI demo
and a deferred statistical Stable/Changing world. Its Capture Sessions,
Timeline windows, baseline handoffs, relationship estimator, `Engine`, query
projections, evidence classification, and restart rules encode a different
product state from the selected RF world model. Adapting those contracts would
make their identities and recovery rules appear authoritative while replacing
their meaning underneath them.

The deployed ESP32-S3 firmware and authenticated native-frame UDP stream are a
real external dependency. They already preserve useful native facts and cannot
be changed merely to make the Host rebuild easier. The RF world model also
needs other source adapters and spatial artifacts without pretending that the
existing ESP measurements contain array, phase, frequency, timing, or geometry
facts they do not provide.

## Decision

Whisper will hard-rebuild every Host contract after authenticated native
observation admission around immutable heterogeneous RF facts, versioned scene
and calibration artifacts, immutable inference inputs, a single joint causal
state model, durable checkpoints, independent world history, and one Rust
writer. There is one cutover. The repository will not implement schema or
state migration, a compatibility layer, legacy endpoints, dual publication, or
parallel old and new world authorities.

The existing device firmware and native-frame v1 UDP contract remain the
external input contract. Firmware capture and serialization, provisioning,
authentication and replay admission, capability and health facts, and lossless
native CSI meanings remain valid at that boundary. Their preservation grants
no authority to the old application, Store, Timeline, relationship, evidence,
or query contracts.

Existing deployments must create a new RF world-model store, import or collect
the spatial and calibration artifacts required by the new specification, and
activate a qualified model combination in a separately initialized directory.
A run command that encounters an old schema fails closed and leaves it
untouched; it does not open for operation, import, upgrade, repair, or delete
that store. Historical stores and executed evidence may be retained read-only
for audit, but their observations, projections, receipts, classifications, and
world state are not promoted into the new system.

Exact operative behavior is owned by the
[RF world-model v1 specification](../specs/rf-world-model-v1.md), and module
ownership by the
[RF world-model architecture](../architecture/rf-world-model.md). Neither
document is a migration plan.

## Superseded decisions

This ADR replaces the following earlier decisions only where they claimed
authority over post-admission Host or world-model behavior:

- [ADR 0002](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0002-engine-single-writer.md): the former `Engine`, Timeline,
  estimator, and WindowProjection ownership is superseded. The rebuilt system
  makes a new single-writer decision for requests, checkpoints, and joint world
  commits.
- [ADR 0003](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0003-sqlite-authoritative-session-store.md): the former Semantic
  Session manifest, ordered-record replay, projection, baseline, and recovery
  authority is superseded. SQLite may remain a private storage mechanism under
  the new schema and commit contract.
- [ADR 0004](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0004-research-promotion-evidence.md): the former promotion gate
  cannot defer or redefine this already accepted architecture. New model
  qualification and acceptance evidence follow the new specification.
- [ADR 0005](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0005-logical-session-fact-bytes.md): Semantic Session rotation and
  its fact-byte identity are removed rather than migrated.
- [ADR 0015](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0015-keep-compatible-host-restart-in-active-session.md): replaying
  old ordered facts to reconstruct an active Semantic Session is replaced by
  epoch termination, an Unknown current projection, and fresh context
  accumulation under the new checkpointed state-chain contract.
- [ADR 0016](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0016-new-capture-session-per-serve.md): per-serve Demo Capture
  Sessions do not define the rebuilt Host lifecycle.
- [ADR 0017](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0017-atomic-capture-ingest.md): the Demo's single admitted-packet
  transaction is replaced by the new fact, request, and result commit seams.

[ADR 0001](0001-native-frame-authentication.md) and
[ADR 0006](0006-bind-replay-admission-to-epoch-key.md) remain applicable to the
preserved native-frame input boundary.
[ADR 0013](0013-trust-program-1-local-store-namespace.md) may inform a reused
local managed-root implementation but grants no authority to the former Store
schema or lifecycle.
[ADR 0014](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/adr/0014-derive-execution-classification-from-claim-graph.md)
continues in fixed history to explain historical Program evidence
classifications; those classifications do not qualify the rebuilt RF world
model.
[ADR 0018](0018-independent-host-supervisor.md) remains applicable to
independent cleanup ownership; its old handle names do not require preservation
of the former runtime or query contracts.
[ADR 0019](0019-maturity-neutral-compatibility-identities.md) remains a naming
principle for new identities and does not preserve any old identity.

## Consequences

- The implementation can express RF measurement truth, model compatibility,
  causal state, expiry, recovery, and history without carrying contradictory
  Demo or statistical-world invariants.
- The fixed deployed firmware remains usable while richer RF hardware enters
  through explicit adapters with its actual capabilities.
- Existing Host clients, tests, stores, fixtures, replay tools, and evidence
  commands that depend on old contracts must be removed or rewritten. Their
  old behavior is not an acceptance target.
- Operators must reprovision Host storage and repeat the calibration and model
  qualification required for the new deployment. An in-place upgrade is not
  offered.
- Historical execution evidence stays inspectable, but it proves only the
  identified former execution and cannot be relabelled as evidence for the new
  system.
- The cutover requires a larger coordinated implementation change and may leave
  the repository temporarily without a runnable end-to-end product while
  replacement tickets land.
- Private implementation code such as lease handling, SQLite mechanics,
  authentication, transport shutdown, or codecs may be reused only when it
  satisfies the new owner and contract without exposing legacy behavior.

## Alternatives considered

**Evolve the former Semantic Program in place.** Rejected because its Timeline,
baseline, Engine, session replay, and query identities encode the wrong state
and would turn extensive semantic replacement into an unreviewable migration.

**Run the old and new worlds together until parity.** Rejected because dual
writers and dual query surfaces create ambiguous production authority and make
old scores look comparable to a different joint-state model.

**Translate old stores and world snapshots into new checkpoints.** Rejected
because the old data lacks the complete immutable input manifests, artifact
compatibility, joint state, and causal predecessor required by the new model.
Inventing them would create false provenance.

**Change firmware and UDP together with the Host.** Rejected because the
deployed native-frame input is a fixed external contract and already preserves
the measurements it actually observes. Richer sensing belongs in additional
Host adapters, not fabricated firmware compatibility.
