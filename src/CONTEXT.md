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

**Demo Slice**:
The bounded delivery maturity from an authenticated physical Sensor to
committed native-coordinate CSI and a read-only browser. It is a scope label,
not an architecture layer, runtime, lifecycle, or capability.
_Avoid_: Semantic Program or Program 1, which name the broader deferred target.

**Semantic Program**:
The deferred delivery scope for the full Program 1 Semantic Session,
temporal/world, query/UI, and formal development-E2E target.
_Avoid_: Demo Slice, which has a smaller operative scope.

**Program 1**:
The contract-local name for the full Single-sensor development E2E target now
assigned to the Semantic Program.
_Avoid_: Demo Slice, which does not satisfy that target.

**Store**:
The persistent identity containing admission, capture, and query history for
the bounded delivery path.
_Avoid_: Demo Store, because delivery maturity is not part of Store identity;
Semantic Store, because no semantic processing is implied.

**Capture Session**:
A non-semantic grouping of admitted packet facts from one uninterrupted Host
capture lifetime.
_Avoid_: Semantic Session or Host process, which have different boundaries.

**Semantic Session**:
A continuity boundary whose ordered facts reconstruct temporal and semantic
state and may span a compatible Host restart.
_Avoid_: Capture Session, which carries no temporal or semantic continuity.

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
A domain event associated with a Semantic Session.
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

**Corpus export**:
A bounded read of immutable packet facts from one sealed session for corpus
construction.
_Avoid_: replay or query, which have different purposes and lifecycle seams.

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
Stopping and reopening the Host process while retaining the selected Store.
_Avoid_: session rotation.
