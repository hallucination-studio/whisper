# Single-sensor development E2E v1 specification

Status: accepted target

This specification is the sole normative owner of Program 1's bounded fixture
cardinality, evidence classifications, and composed physical-to-browser
acceptance. It does not redefine the component contracts it composes, claim
that the target is implemented, or claim that an acceptance run has executed.

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

`Program 1` is the delivery-scope short name for the Single-sensor development
E2E acceptance specified here. It does not name a domain object or runtime mode.

## Program 1 fixture

Program 1 acceptance uses exactly one physical Sensor, one authenticated route,
and one Link/Profile path through the production Host to the diagnostic Web.
This is a Single-sensor deployment acceptance fixture, not a single-sensor
runtime mode or product cardinality limit.

Configuration arrays, storage keys, schemas, API representations, UI
collections and selectors, runtime ownership, and resource formulas MUST remain
dynamic in Sensor count. They MUST NOT special-case one Sensor, assume that the
first Sensor is the only Sensor, or impose a product maximum of one or two
Sensors. Program 1 resource receipts MUST state the actual one-Sensor route,
Link, and Profile load that they exercised.

Program 1 acceptance does not require two routes, two Profiles, or two physical
Sensors. Generated scenarios MAY use multiple routes or Profiles to test
isolation and dynamic layout without changing the physical fixture or becoming
hardware evidence. Physical Multi-sensor deployment acceptance is future scope
owned by the [roadmap](../ROADMAP.md#multi-sensor-deployment-validation).

## Evidence modes

Every Program 1 E2E input artifact and execution receipt MUST use exactly one
of these normative classifications:

| Classification | Required source and supported claim |
| --- | --- |
| `board-capture-smoke` | A contemporaneous physical ESP32-S3 emits capabilities and CSI datagrams that production Rust admission and decoding accept. It does not prove browser, restart, resource, soak, or release behavior. |
| `captured-corpus-e2e` | Immutable encrypted datagrams previously captured from the identified physical board traverse the production Host-to-Chrome path. It is captured hardware data, but not a contemporaneous live physical run. |
| `scenario-e2e` | Deterministically generated inputs exercise difficult states through production-shaped seams. They are neither captured hardware data nor physical proof. |
| `live-physical-e2e` | A newly emitted observation from the identified physical Sensor reaches a visibly updated Chrome page through the production path during the retained interval. |

One classification MUST NOT satisfy another classification's physical or live
step. In particular, corpus replay and generated scenarios MUST NOT satisfy
`live-physical-e2e`, and generated scenarios MUST NOT satisfy
`board-capture-smoke` or `captured-corpus-e2e`. Test source remains distinct
from executed evidence; every executed claim requires its own immutable receipt
as defined by the relevant evidence authority.

An accepted captured corpus contains the exact encrypted datagrams emitted by
the identified physical board plus their peer and receive context. Its
versioned manifest MUST bind the firmware revision and image digest, controlled
board and Sensor identity, route and configuration identity, Link/Profile,
datagram order and individual hashes, capture time, and capture-tool identity.
Changing content, order, or provenance creates a new corpus version; an accepted
corpus version is immutable.

Corpus fixtures MUST use controlled identities and locally administered MAC
addresses. SQLite database bytes are never a corpus artifact. Captured corpora
and generated scenarios MUST retain their distinct classifications in manifests
and receipts.

A `live-physical-e2e` receipt MUST bind the controlled board and Sensor,
firmware revision and image digest, provisioning and route/configuration
identity, Link/Profile, the fresh datagram and receive interval, Host revision
and executable, Chrome version, capture and runner tool identities, timestamps,
browser interactions, trace and network activity, screenshots, and artifact
digests sufficient to reconstruct the run.

All four modes MUST satisfy the secret and sensitive-artifact exclusions owned
by [native-frame v1](native-frame-v1.md#provisioning-and-image-compatibility) and
[host persistence v1](persistence-v1.md#program-1-development-secret-store).

## Composed acceptance

Program 1 selects the deterministic development fixture key and ordinary
firmware provisioning contract from [native-frame v1](native-frame-v1.md), the
temporary secret-store and minimal Host restart contracts from
[host persistence v1](persistence-v1.md), the read-only diagnostic Web and real
Chrome recovery contract from [API/UI v1](api-ui-v1.md), and the current-Mac
resource contract from [evaluation v1](evaluation-v1.md). Those specifications
remain the sole owners of their exact component behavior.

Program 1 completes only with repeatable `captured-corpus-e2e` and
`scenario-e2e` coverage, the independent `board-capture-smoke` boundary, and
one reconstructable `live-physical-e2e` receipt. Their presence as accepted
targets in this specification is not evidence that any run occurred.
