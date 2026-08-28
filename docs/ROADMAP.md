# Whisper roadmap

This document is the sole owner of Whisper's deferred and conditional product,
research, hardware, security, and release directions. A roadmap entry is future
intent, not an accepted behavior contract, implementation claim, or active work
item.

Current statistical baseline, world, replay, and positive resource-budget
behavior remains in [temporal world v1](specs/temporal-world-v1.md). Current
evaluation and leakage behavior remains in [evaluation v1](specs/evaluation-v1.md).
Current ESP32-S3 development image and provisioning behavior remains in
[native-frame v1](specs/native-frame-v1.md).

## Promotion rule

A future direction moves out of this roadmap only after all of these are true:

1. The prerequisite data, hardware, consumer contract, or measured limitation
   exists and is retained with provenance.
2. A bounded experiment or operational procedure produces independently
   reviewable evidence against the current accepted path.
3. A maintainer makes the explicit scope and authority decision identified by
   the entry; an external paper, lower loss, available library, or prototype is
   not that decision.
4. The accepted bytes, schema, behavior, evaluation, and failure semantics are
   written in a versioned specification without changing an existing version's
   meaning.
5. GitHub Issues are created for the resulting implementation, dependencies,
   blockers, and missing execution evidence.

Until then, there is no implementation issue merely because a direction is
listed here. The rationale for this evidence threshold is recorded in
[ADR 0004](adr/0004-research-promotion-evidence.md). External source identity
and provenance lives in the [references index](references/README.md).

## Multi-sensor deployment validation

### Direction

After the Single-sensor deployment Program completes and a second-board
environment is identified, validate one bounded Multi-sensor deployment with at
least two independently provisioned physical Sensors through capture,
durability, temporal/world semantics, query delivery, and the diagnostic Web.
Two Sensors are the minimum evidence point for that later Program, not a product
maximum or a transport topology.

The accepted [development E2E v1 specification](specs/development-e2e-v1.md)
keeps configuration, schemas, APIs, collections, selectors, runtime ownership,
and resource formulas dynamic in Sensor count. This roadmap entry owns only the
deferred physical Multi-sensor deployment acceptance.

### Promotion gate

- Identify two physical Sensors, their independent provisioning, routes,
  Links/Profiles, firmware images, and controlled network environment.
- Prove Sensor, route, Link, and Profile isolation through storage, Engine
  state, queries, browser selection, and Host restart without first-Sensor bias.
- Retain a physical-to-browser receipt that binds both hardware sources and the
  actual resource load while disclaiming multi-board soak and release capacity.
- Create detailed implementation and evidence issues only after board ownership,
  serial ports, WLAN, credentials, and the supported acceptance deployment are
  known.

## Release security and OTA

### Direction

Move from the accepted disposable development profile to a production release
profile with a signed shared-image manifest, release-key roles, Secure Boot v2,
flash encryption, eFuse policy, encrypted production provisioning, signed OTA
with rollback, and explicit factory/recovery ceremonies.

The development partition flags, unsigned image, and disposable credentials
remain defined by native-frame v1; their presence is not production at-rest or
release security evidence.

### Promotion gate

- Retain a threat model, supported target/board identity, key-role and recovery
  policy, provisioning lifecycle, and rollback/failure analysis.
- Pin the applicable Espressif security and OTA sources by version and date.
- Demonstrate the complete ceremony on disposable hardware, including failed
  signature, interrupted update, rollback, key loss, and reprovisioning cases.
- Decide the release authority, key custody, rotation, device-recovery policy,
  and compatibility boundary.

Promotion creates a versioned release-security/OTA specification and separate
implementation and physical-evidence issues. It does not change the sensing
datagram into an update transport.

## Release performance and soak

### Direction

Add callback and encoder latency measurements, runtime histograms, tail-latency
and capacity reports, fixed reference hardware, sustained packet-bound and
byte-bound workloads, and long-running multi-board soak gates.

The positive v1 RSS, CPU-thread, and snapshot-deadline configuration remains in
temporal world v1. This entry owns only the deferred release measurements and
support envelope.

### Promotion gate

- Complete and retain v1 capture-to-world acceptance on a fixed corpus before
  measuring optimization candidates.
- Identify the minimum/reference CPU, OS, storage, power/frequency policy,
  route/profile topology, query load, and real maximum-size fixtures.
- Prove that instrumentation itself does not alter semantic input or outputs.
- Retain packet-bound, byte-bound, replay, failure-count, peak-RSS, tail-latency,
  storage-growth, and multi-board soak results long enough to reconstruct them.
- Decide the supported hardware/load envelope and which measurements become
  release-blocking.

Promotion creates a versioned release-performance specification and bounded
measurement/optimization issues. A desktop estimate or unretained run cannot
promote the gate.

## CPU self-supervised candidate

### Direction

Evaluate a small native-coordinate forecast candidate from sealed-session
faithful replay, initially as an immutable artifact and bounded shadow path.
The accepted statistical estimator remains the production authority while this
direction is future.

### Promotion gate

- Complete the v1 Engine, evidence, semantic replay, and retained acceptance
  gates so one audited input stream can be reused by the incumbent and candidate.
- Retain enough later sessions for time-forward train/holdout evaluation with
  no split or baseline-fit leakage.
- Demonstrate improvement over the simplest incumbent without hiding loss in
  coverage or abstention, and meet the target CPU, RSS, artifact, and replay
  budgets.
- Specify immutable artifact identity, eligibility, reset, failure, fallback,
  selection, rollback, retention, and session-boundary behavior.
- Decide whether the result is worth a candidate slice and whether it remains
  shadow-only.

Any influence on Stable/Changing production semantics requires a separate
semantic ground-truth set and an explicit fusion or replacement decision. On
promotion, a versioned candidate specification and implementation/evidence
issue graph own the selected behavior.

## RF pretraining

### Direction

Investigate offline RF pretraining from sealed, provenance-preserving sessions,
starting with one real profile and a native-coordinate forecast probe. Internal
packing, latent dimensions, adapters, and training heads remain artifact-private
research choices rather than domain or session schema.

The following topology entries route future experiments only. They do not
select a training architecture, define an artifact schema, or create a runtime
contract.

### Offline packing and representation

Evaluate deterministic, artifact-private episode packing and continuous
representations without turning packed widths, latent dimensions, adapters, or
training tokens into domain facts. Promotion evidence must show that native
identity, coordinates, masks, actual time, uncertainty, exclusions, ordering,
and source receipts survive the derivation and that unsupported or missing
facts are not inferred.

### Causal behavior and core

Start topology comparisons with one simple causal path and a native-coordinate
forecast probe. Reconstruction, masked-latent, or simulation surfaces remain
offline evaluation choices and cannot promote a core without independent
forecast evidence against the accepted statistical path.

### RSSM candidate

Consider RSSM-style separation of causal memory, prior, and posterior only
after retained evidence shows that the simpler causal path needs longer state.
Lower reconstruction loss or the availability of an RSSM implementation is not
that longer-state evidence.

### MoT candidate

Consider objective-specific mixture-of-transformers blocks only after measured,
reproducible objective conflict or holdout negative transfer establishes that
one shared core is insufficient. MoT remains a replacement experiment, not a
default topology or a parallel production core.

### Mamba candidate

Consider Mamba or another state-space core only after profiling proves that the
current recurrent core's long-sequence throughput or memory is the relevant
bottleneck. Library availability or asymptotic complexity alone is not that
evidence, and the candidate remains a replacement experiment.

### Promotion gate

- Retain a sufficiently varied corpus and evaluation manifest covering device,
  profile, deployment, room, session, and time-forward groups.
- Compare the simplest continuous representation and causal path against the
  accepted statistical path and CPU candidate on the same forecast/evidence
  meaning.
- Preserve native identity, coordinates, masks, time uncertainty, exclusions,
  and receipts through every training example.
- Review licenses and data provenance for every external code, weight, output,
  or service input.
- Decide the narrow pretraining objective and artifact role from evidence; a
  named public architecture does not select the implementation.

Promotion creates a versioned offline-training and artifact specification. An
offline artifact does not acquire production-world authority by promotion.

## CPU deployment model and compression

### Direction

Only if statistical and small CPU candidates are insufficient, evaluate one
CPU deployment artifact with an independently measured inference path.
Quantization, pruning, structured compression, or output distillation are
alternatives to test, not required stages.

### Promotion gate

- Retain evidence that the simpler accepted paths miss a specified forecast or
  semantic requirement.
- Produce an independently trained deployment baseline before attributing value
  to pretraining or distillation.
- Measure complete-stream latency, RSS, threads, allocation, integrity,
  unsupported-input behavior, fallback, state reset, and replay on the target CPU.
- For compression or distillation, compare the uncompressed deployment
  baseline and the transformed artifact on the same split and target behavior.
- Decide one artifact/runtime path; multiple speculative model backends or
  temporal cores are not promoted together.

Promotion creates a versioned deployment-artifact specification and a bounded
runtime/evidence graph. Production selection remains explicit at a session
boundary.

## Intel 5300 acquisition

### Direction

Add a real Intel 5300 transport and decoder that maps only proven device facts
to the existing dynamic CSI domain, then evaluate mixed ESP32/Intel operation.
The v1 in-memory dynamic-shape compatibility case is not evidence of acquisition
support.

### Promotion gate

- Obtain the actual hardware, driver/protocol source, capture procedure, and
  retained raw fixtures with pinned provenance.
- Prove sample encoding, physical tone/path identity, timestamps, phase state,
  sequence behavior, and failure classes without inferring them from shape.
- Exercise domain, Timeline, conditioning, estimator, evidence, query, and
  replay paths with the real profile.
- Decide the transport/capability boundary and supported hardware revision.

Promotion extends a versioned capture/protocol specification and creates the
decoder, fixture, mixed-profile, and hardware-evidence issue graph.

## Clock, phase, and coherent fusion

### Direction

Evaluate corrected capture time, phase calibration, and coherent fusion only
for hardware that can expose a common clock/LO or a measured mapping and
calibration error bound. Current non-coherent belief aggregation remains the v1
path.

### Promotion gate

- Retain synchronized captures, physical reference/calibration procedure,
  mapping identity, drift and uncertainty bounds, and repeatability evidence.
- Demonstrate benefit over independent per-link evidence and conservative
  aggregation on held-out physical episodes.
- Specify explicit abstention when clock, topology, or calibration receipts are
  missing or outside bounds.
- Decide the supported coherence group and whether the result changes only
  diagnostics or production world semantics.

Promotion creates a versioned timing/calibration/fusion specification and
hardware/calibration/evaluation issues.

## Learned multi-link fusion

### Direction

Investigate learned cross-link aggregation only after synchronized,
topology-aware multi-link data exists. Different profiles of one physical link
remain one coverage source unless a future accepted contract proves otherwise.

### Promotion gate

- Retain synchronized multi-link episodes, topology calibration, alignment
  uncertainty, missing-link cases, and semantic ground truth.
- Compare permutation-invariant learned aggregation against the accepted
  conservative physical-link rule on held-out devices, profiles, rooms, and
  sessions.
- Demonstrate explicit behavior for missing, incompatible, skewed, or
  over-budget inputs and preserve source contributions.
- Decide the representation compatibility and production fusion rule.

Promotion creates a versioned learned-fusion specification and separate corpus,
implementation, and semantic-evidence issues.

## Multimodal sensing

### Direction

Consider a second concrete sensing modality only when its native fact source,
identity, time, quality, provenance, and operational need exist. Shared offline
representations may then be evaluated on paired, aligned episodes; live typed
evidence remains independently abstainable.

### Promotion gate

- Identify a real second modality and its authoritative bytes/observations,
  deployment owner, privacy/security constraints, and independent acceptance path.
- Retain paired episodes with alignment receipts and independent holdouts for
  every source.
- Demonstrate benefit beyond late fusion without hiding missing or unsupported
  inputs and without generating replacement facts.
- Decide the concrete modality contract, pairing/alignment policy, and live
  versus offline scope.

Promotion first creates the modality's own versioned fact specification and
issues. A shared representation or fusion specification follows only after the
paired-data gate passes.

## Calibrated semantic outcomes

### Direction

Presence, motion semantics, out-of-distribution claims, count, identity, pose,
gesture, falls, respiration, heart rate, geometry, and three-dimensional
reconstruction remain outside the accepted Stable/Changing/Unknown world state.

### Promotion gate

- Identify one concrete user outcome and its error costs.
- Retain representative ground truth, calibration, grouped holdouts, and a
  failure/abstention policy across the claimed deployment scope.
- Demonstrate that RF quality, missingness, device/profile shortcuts, and target
  calibration are reported rather than hidden.
- Decide the exact semantic vocabulary, supported scope, and whether it belongs
  in world state, a derived product, or neither.

Promotion creates a new versioned semantic specification and separate data,
implementation, evaluation, and product-acceptance issues.

## Additional product surfaces

Long-history indexing, multiresolution caches, late state revision, alerts,
external automation integrations, multitenant authorization, geometric scenes,
and active sensing require a real consumer contract before design.

Promotion requires the external consumer, retention and consistency needs,
security/privacy constraints, failure semantics, and measured limitation of the
current bounded query path. The decision selects one narrow surface and creates
its versioned specification and issue graph; the entries are not bundled into a
general platform project.
