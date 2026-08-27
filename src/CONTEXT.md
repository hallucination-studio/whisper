# Rust host

This context names the concepts used to discuss host-side sensing and replay.
It exists to keep host domain language consistent.

## Language

**Deployment**:
A named sensing installation that groups related links.

**Link**:
A configured RF observation relationship within a deployment.
_Avoid_: device, when the relationship rather than the hardware is meant.

**Profile**:
A capture-semantics compatibility boundary used to interpret observations from
a link.
_Avoid_: deployment or link, which identify different domain concepts.

**Replay configuration**:
The part of configuration that describes replay semantics.
_Avoid_: runtime configuration.

**Runtime configuration**:
The part of configuration that describes operating the host without defining
replay semantics.
_Avoid_: replay configuration.

**Captured packet**:
The host-domain representation of one received native frame and its receive
context.
_Avoid_: raw datagram.

**Session record**:
A domain event associated with a sensing session.
_Avoid_: packet, because not every session event represents captured data.

**Baseline state**:
The estimator's domain state for a link and profile.
_Avoid_: snapshot, when referring to the state concept rather than a view of it.
