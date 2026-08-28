# Temporal world runtime evidence index

This index distinguishes implementation facts, checked-in test source, executed
evidence, accepted targets, and WIP for temporal world v1. It owns no temporal,
estimator, runtime, replay, or evaluation behavior.

## Snapshot classification

Baseline revision: `f83428c31aba285277fc95db4079228b97ecaa62`

Classification date: 2026-08-27

The classifications below use committed files at that revision; the dirty
working tree is classified separately as WIP. At this revision, code plus
behavior-test source establishes typed time and world values, dynamic CSI
construction, validated future-stage configuration, baseline command/snapshot
session values, and selected constructor invariants. It does not establish a
Timeline, conditioning transform, statistical estimator behavior, Engine,
semantic replay runtime, or application/server runtime.

No repository-retained Cargo or product runtime execution receipt was
identified for this baseline. Checked-in test source therefore remains test
source, not a passing result.

## HEAD implementation and test source

| Surface | Implementation at baseline | Directly relevant test source | Maturity |
| --- | --- | --- | --- |
| Session-monotonic time, half-open intervals, explicit receive/corrected event time | `src/domain/time.rs` | `src/domain/tests/time.rs` checks receive-time consistency, mapping requirements, and interval behavior | implemented fact plus test source |
| Dynamic CSI coordinates and profile identity | `src/domain/csi.rs` | `src/domain/tests/csi.rs` constructs a `3 x 3 x 30` capture with 270 coordinates and checks profile identity | implemented fact plus test source; no temporal path |
| Window, conditioning, quality, baseline, and resource configuration values | `src/config.rs:457-712`, validation at `1321-1486` | `tests/config_validation.rs` checks canonical semantic config identity and selected numeric guards | implemented configuration; execution and several behavior guards open |
| Typed knowledge, baseline status/commands/snapshot, quality, evidence, link/space belief, and WorldSnapshot values | `src/domain/world.rs:15-1481` | `src/domain/tests/world.rs:61-422` checks constructor identity, ordering, finite-value, and receipt invariants | implemented values plus test source; no estimator or aggregation behavior |
| Ordered baseline commands, immutable baseline snapshots, and TimelineAdvance session record variants | `src/session.rs` | inline session tests check strict roundtrip and selected sequence/time/closed behavior | implemented session values plus test source; no semantic replay |
| Native-frame dynamic decode and post-authentication route rejection | `src/wire.rs` | inline wire tests cover dynamic fixtures, parser failures, profile separation, capability, and source/radio rejection | implemented fact plus test source; downstream baseline exclusion unproved |
| Timeline, conditioning, estimator, Engine, application runtime, semantic replay equality | no baseline module or runtime interface exists | no directly runnable end-to-end test at the owning semantic seam | accepted target; implementation open |

Constructor tests prove only the values and invariants they exercise. In
particular, `WorldSnapshot::try_new` does not prove that one snapshot is
generated per global window; `LinkStepEvidence::try_new` does not prove an
estimator emitted it; all-prefix wire parsing does not prove all-prefix
admission; route rejection does not prove downstream baseline exclusion.

The statistical production path and current process resource configuration are
v1 accepted targets in [temporal world v1](../specs/temporal-world-v1.md). At the
baseline revision the configuration enforces positive RSS/thread/deadline
values and `snapshot_deadline <= 0.5 * window step`, but no runtime or retained
measurement demonstrates that deadline.

## Executed evidence

No repository-retained temporal/world execution receipt was identified for the
baseline revision. The protected implementation plan's historical `PASS` and
progress statements are not receipts. Issue #1 also reports prior aggregate
host test counts, but without an immutable revision/environment/command/artifact
receipt they do not establish any Timeline, estimator, Engine, replay, or
end-to-end gate.

The missing execution surface includes focused Timeline, conditioning,
estimator, Engine, rollback/recovery, live-versus-replay, multi-route/profile,
resource-budget, and end-to-end receipts. The dedicated evidence child issue
[Issue #23](https://github.com/hallucination-studio/whisper/issues/23) is the
live owner of that gap.

## Historical WIP boundary

At its initial classification time on 2026-08-27, the working tree snapshot
contained this then-complete unstaged/untracked delta:

```text
M  Cargo.lock
M  Cargo.toml
M  src/config.rs
M  src/domain/world.rs
M  src/lib.rs
M  src/session.rs
M  tests/config_validation.rs
M  tests/fixtures/config/valid-two-esp32.toml
D  tests/fixtures/session/session-v1.hex
?? src/database.rs
?? firmware/esp32-native-frame/__pycache__/
?? firmware/esp32-native-frame/tests/__pycache__/
```

That historical WIP snapshot is broader than a baseline-value change: it
includes uncommitted
SQLite/persistence implementation and tests, session/config changes, a proposed
complete baseline state, fixture changes, generated bytecode, and dependency
wiring. It is evidence of work in progress only. Subsequent worktree changes,
including Timeline and application work, are intentionally outside this
snapshot. None of the snapshot's contracts, implementation, test source, or
observed behavior was adopted into the architecture or v1 specifications, and
none is an implemented fact at `f83428c`.

## Active gates

GitHub Issue #4 is the domain parent. Its bounded child issues own the open
work:

- [#18 Timeline](https://github.com/hallucination-studio/whisper/issues/18);
- [#19 conditioning](https://github.com/hallucination-studio/whisper/issues/19),
  blocked by #18;
- [#20 statistical estimator and world aggregation](https://github.com/hallucination-studio/whisper/issues/20),
  blocked by #19;
- [#21 single-writer Engine/runtime](https://github.com/hallucination-studio/whisper/issues/21),
  blocked by #20 and requiring the persistence implementation seam recovered
  under #6;
- [#22 faithful semantic replay](https://github.com/hallucination-studio/whisper/issues/22),
  blocked by #21 and requiring the persistence replay-input seam recovered
  under #6; and
- [#23 retained acceptance evidence](https://github.com/hallucination-studio/whisper/issues/23),
  blocked by #18 through #22 and the applicable persistence evidence.

The exact accepted behavior is in
[temporal world v1](../specs/temporal-world-v1.md), evaluation and leakage rules
in [evaluation v1](../specs/evaluation-v1.md), and non-discoverable ownership in
[world/runtime architecture](../architecture/world-runtime.md).
