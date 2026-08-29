# Temporal world evaluation v1 specification

Status: accepted target

Applicability: all calibration, data-split, leakage, semantic replay, World
evaluation, and runtime qualification behavior in this document belongs to the
deferred Semantic Program, called Program 1 within the preserved v1 contracts.
The bounded Demo has no evaluation contract and a `demo-smoke` result cannot
satisfy or promote this target.

This specification is the sole normative owner of v1 evaluation, calibration,
and leakage behavior for the statistical temporal/world runtime. It does not
define Timeline, estimator, or world behavior; those contracts live in the
[temporal world v1 specification](temporal-world-v1.md).

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Evaluation manifest

Every threshold calibration, replay comparison, and semantic evaluation MUST
retain a manifest that identifies:

- deployment, space or room, and day;
- device hardware, firmware, boot generation, and session;
- physical link, channel, and capture profile;
- trial and label provenance when labels exist;
- calibration partition and exact session/window references;
- target-domain data use as `none`, `unlabeled calibration`, or
  `labeled few-shot`;
- quiet/normal command provenance and operator when applicable;
- decoder, conditioning, algorithm, baseline, and window contract versions;
- split assignment, grouping keys, and seed; and
- executable build/target and replay-configuration identity.

Missing provenance makes the affected claim ineligible. A report MUST NOT fill
missing identity or grouping facts by inference from a file name, device count,
or CSI shape.

## Split before derivation

The split MUST be assigned before preprocessing, baseline fit, windowing,
normalization, augmentation, sampling, threshold selection, or any other
derived-data construction.

All records from the same declared evaluation group MUST remain in one split.
The grouping policy MUST include every dependency relevant to the claim, chosen
from deployment, room, day, device, boot, session, person, trial, and physical
episode. Multiple links or profiles observing one physical episode and time
interval MUST remain together.

Calibration windows MUST NOT overlap test windows. Overlapping windows MUST NOT
cross splits. Reciprocal views or repeated samples from one physical trial MUST
NOT be separated when that would expose the same event to train/calibration and
test. Randomly splitting frames before window construction is leakage and MUST
NOT support a generalization claim.

## Calibration and thresholds

All nontrivial estimator defaults and thresholds MUST be justified by a retained
calibration corpus, procedure, result, and provenance. Values MUST NOT be copied
from an external publication or another deployment without an evaluation that
establishes applicability to the supported contract.

Baseline fit and threshold selection use calibration partitions only. Test data
MUST remain unavailable until the calibration procedure and decision rule are
fixed. A test result MUST identify the exact baseline, conditioning, window,
quality, and algorithm contracts used.

The report MUST expose coverage and abstention alongside Stable/Changing
outcomes. An improvement MUST NOT be obtained by silently excluding more
coordinates, profiles, links, windows, or sessions. Unknown reasons, gap and
missing behavior, and baseline lifecycle transitions MUST be reported rather
than discarded.

## Target-domain claims

Reports MUST distinguish:

- `no target data`: no target deployment data affected fit, calibration,
  threshold selection, or model selection;
- `unlabeled target calibration`: target data affected baseline or threshold
  calibration without semantic labels; and
- `labeled few-shot`: target labels affected a decision.

A result that used a target room's quiet/normal bootstrap or thresholds MUST
NOT be called zero-shot or no-target-data. The report MAY describe the exact
calibration regime without assigning a broader name.

## V1 evaluation surfaces

### Semantic replay

Live and faithful replay comparison MUST use the same sealed session, complete
initial baseline states, executable, target, and semantic identity. Comparison
MUST cover typed snapshots, link evidence, Timeline state, and complete baseline
state after removing only non-semantic delivery and processing metadata.

The Program 1 corpus MUST include its one authenticated route and Profile,
explicit baseline commands, a source gap, and a device-epoch boundary. Profile
change and multi-route or multi-Profile isolation MAY be exercised with
generated scenarios, but are not additional physical-fixture requirements and
MUST retain their distinct evidence classification. Each expected isolation
and Unknown result MUST be stated before execution. Fixture cardinality and
evidence classifications are owned by the
[development E2E v1 specification](development-e2e-v1.md).

### Statistical world behavior

World evaluation MUST report per-profile eligibility, per-link status, physical
link coverage, per-space status, contributions, exclusions, and baseline
lifecycle. Aggregate success MUST NOT hide one device, profile, or link.

Evaluation MUST include different devices, profiles, restarts, sessions, and
rooms or spaces where the claim spans them. A single stable deployment can
establish deterministic mechanics but cannot establish cross-deployment or
cross-room behavior.

### Runtime resource contract

Any deadline or resource claim MUST identify the actual target host, operating
system, CPU/thread policy, memory limit, executable profile, route/link/profile
load, packet rate, coordinate bounds, window timing, query load, and corpus
digest. Desktop extrapolation, a synthetic no-op path, or an average without
tail observations MUST NOT establish the v1 snapshot deadline.

The result MUST report missed deadlines, input loss, unexplained sequence gaps,
write failures, and peak RSS. A resource run is invalid if meeting the budget
changes semantic input, estimator behavior, or retained facts.

Program 1 applies this contract to the current Apple Silicon Mac identified by
the receipt. In addition to the fields above, the receipt MUST identify the
exact Mac model, architecture, macOS, Rust, Node, and Chrome versions and report
thread count, tail observations, and client backpressure. The result MUST state
the actual one-Sensor route/Link/Profile load and MUST NOT claim production
performance, release capacity, long-duration soak, or Multi-sensor deployment
acceptance.

## Evidence record

An executed evaluation receipt MUST identify the repository revision,
executable and target, environment, manifest and corpus digests, exact command
or procedure, start time, result, and retained artifacts sufficient to audit
the claim. Test source, a plan status, console prose without artifacts, or an
unidentified prior run is not an executed receipt.

Each report MUST state the narrow claim it supports. Passing constructor tests
does not establish estimator behavior; passing semantic replay does not
establish calibration quality; passing a resource run does not establish a
semantic generalization claim.
