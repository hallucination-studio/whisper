---
status: accepted
---

# Keep compatible Host restart inside the active session

Scope: this decision applies only to a deferred Semantic Session. A Demo Host
restart creates another non-semantic Capture Session under
[ADR 0016](0016-new-capture-session-per-serve.md); it does not recover or
continue the prior Capture Session.

## Context

Timeline watermarks, open fixed windows, stream instances, estimator arming,
and World identity are semantic state reconstructed from one session manifest
and its ordered facts. Treating process restart as session rotation would make
Host process lifetime a semantic boundary and could discard an open window,
even though neither the Sensor nor the sensing configuration changed.

## Decision

A Host restart whose replay identity exactly matches the active manifest
reconstructs fresh working state and continues that same active session. A
replay-identity mismatch fails closed; it does not append `Closed`, seal the
session, or manufacture a successor. Exact recovery, continuation, and evidence
behavior is owned by the
[host persistence v1 specification](../specs/persistence-v1.md).

## Consequences

- Process lifetime does not enter semantic identity.
- The next new durable record continues after the recovered durable tail in the
  same session and record-sequence space.
- Explicit finish and configured duration or byte limits remain the only v1
  rotation triggers.

## Alternatives considered

**Seal and create a successor on every restart.** Rejected because a restart
inside an open Timeline window would change semantic output relative to an
uninterrupted run and would make restart recovery depend on an unnecessary
inter-session handoff.
