# Rust host

This context names the concepts used to discuss host-side sensing and replay.
It exists to keep host domain language consistent.

## Language

**Deployment**:
A named sensing installation that groups related links.

**Sensor**:
A configured sensing endpoint within a deployment.
_Avoid_: mesh node, because no transport topology is implied.

**Single-sensor deployment**:
A deployment configured with exactly one sensor.
_Avoid_: single-device mode, because it is not a distinct runtime mode.

**Multi-sensor deployment**:
A deployment configured with more than one sensor.
_Avoid_: mesh, because sensor count does not imply a network topology.

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

**Managed database**:
The SQLite file selected for `HostLifecycle` operations.

**Managed store root**:
The dedicated trusted local directory containing one Managed database, its
SQLite companions, and its cooperative lifecycle lease.
_Avoid_: security boundary, because Program 1 does not isolate the root from a
hostile process with the same filesystem credentials.

**Store ID**:
The stable non-secret identity assigned when a Managed database is provisioned.
_Avoid_: credential or attestation, because possession of the value proves no
authority or physical origin.

**Store topology manifest**:
The immutable provisioned Deployment, Space, Transmitter, Sensor, and Link
identity set associated with a Managed database.
_Avoid_: runtime configuration.

**Projection watermark**:
The Store ID plus a monotonic sequence naming one query-visible Store state.

**Committed projection identity**:
A Projection watermark whose sequence is nonzero and names a committed change.

**Corpus input lineage**:
The declared origin and derivation chain of immutable corpus content.
_Avoid_: evidence classification, which is issued only from an executed claim
graph.

**Executed claim graph**:
A verifier-checked graph whose typed claims and artifact references support one
execution-result classification.
_Avoid_: corpus manifest or receipt blob, neither of which can classify itself.

**Evidence package**:
A retained collection of artifacts used to verify Executed claims.
_Avoid_: digest list, because unresolvable digests retain no inspectable proof.

**Host commit trace**:
A procedural record of identified committed Host operations.
_Avoid_: database timestamp or attestation.

**Session fact bytes**:
The logical size of one session's authoritative manifest and ordered records.
It is independent of storage-engine space usage.

**Baseline handoff**:
The complete estimator state passed from a finished session to its successor
without changing its identity or meaning.

**Pending baseline handoff**:
A completed Baseline handoff held between a sealed session and its successor.
_Avoid_: Baseline state projection, which is rebuildable query state rather than
inter-session bootstrap authority.

**Recovered tail**:
The ordered durable facts after an active session's committed processing cursor.

**Host restart**:
Stopping and reopening the Host process while retaining the Managed database
and replay identity.
_Avoid_: session rotation.
