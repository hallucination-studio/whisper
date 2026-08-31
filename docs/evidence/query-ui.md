# Query and UI evidence index

- Status: evidence gaps open
- Target contract: [`../specs/api-ui-v1.md`](../specs/api-ui-v1.md)
- Tracking issue: [#5](https://github.com/hallucination-studio/whisper/issues/5)
- Implementation snapshot inspected: `f83428c31aba285277fc95db4079228b97ecaa62`

This index separates source availability from executed evidence. It is not an
execution receipt and does not turn an accepted target into current behavior.

## Executed demo-smoke

The [physical `e151145` demo-smoke](receipts/demo-smoke-e151145/README.md)
retains one sanitized real-board-to-unchanged-Chrome execution. The page was
loaded once with no signal rows, then visibly updated to `LIVE` through the
committed Host path. Its exact receipt, final HTTP bodies, and screenshot are
retained together. This result has only the bounded `demo-smoke`
classification stated by that receipt.

## Clean HEAD implementation facts

At the identified HEAD, the crate declares `capture`, `config`, `domain`,
`session`, and `wire` modules. It has no query projection module, HTTP server,
WebSocket runtime, runtime composition module, web asset tree, or diagnostic UI
consumer. Its manifest has no HTTP/WebSocket server stack or async runtime.

HEAD does contain validated runtime configuration values for view limits,
server binding, command queue capacity, and WebSocket queue capacity. Those
values are marked for later work-package consumers. Configuration source alone
does not implement or exercise a query/API/UI runtime.

The worktree also contains an unstaged product-code delta, including an
untracked database source file. That delta is WIP: it is not part of the
identified HEAD, was not used as implementation authority, and establishes no
query/API/UI fact or evidence.

## Accepted wire target

The accepted API/UI specification now incorporates a complete JSON Schema
2020-12 artifact for the v1 HTTP and WebSocket DTO profile. This is an accepted
target only. Neither clean HEAD nor the current WIP implements the DTOs,
strict runtime validation, endpoint envelopes, JavaScript consumer, or
cross-language fixtures, and no execution receipt proves them.

## Evidence classes

| Class | What would establish it | Current state at the inspected snapshot |
| --- | --- | --- |
| Test source | Checked-in behavior tests for query, server, WebSocket, or web behavior | Absent for the query/API/UI target |
| Host execution | Immutable receipt naming revision, environment, command, result, and artifacts | No query/API/UI execution receipt retained |
| Browser execution | Receipt naming revision, browser/version, served build, fixtures, assertions, and retained screenshots/trace | Open |
| Disconnect/resync execution | Receipt showing a delivery gap or disconnect, HTTP refresh, returned receipt, and no synthetic/live-stale confusion | Open |
| End-to-end execution | Receipt tracing admitted capture-derived facts through committed projections, HTTP, WebSocket invalidation, and browser rendering | Open |

Existing domain/configuration/session/wire test source is not query/API/UI test
source. A historical test count or `PASS` statement, without an immutable
receipt covering this surface, is not query/API/UI executed evidence.

## Open gates

| Issue | Gate |
| --- | --- |
| [#12](https://github.com/hallucination-studio/whisper/issues/12) | Read projections, query semantics, and behavior-focused test source |
| [#14](https://github.com/hallucination-studio/whisper/issues/14) | HTTP/WebSocket runtime composition and slow-client isolation |
| [#15](https://github.com/hallucination-studio/whisper/issues/15) | Diagnostic UI implementation and UI test source |
| [#16](https://github.com/hallucination-studio/whisper/issues/16) | Executed browser and disconnect/resync receipt |
| [#17](https://github.com/hallucination-studio/whisper/issues/17) | Executed capture-to-browser end-to-end receipt |
| [#36](https://github.com/hallucination-studio/whisper/issues/36) | Decision publication history; strict Rust/browser validators, boundary fixtures, and cross-language execution evidence remain absent |

## Required receipts

### Query and HTTP

Retain the exact revision, database fixture/corpus identity, server
configuration, command lines, result, and relevant output artifacts. The run
must cover invalid queries, typed empty/unknown, unavailable ranges, dynamic
multi-profile signal tiles, missing-versus-zero, snapshot-pinned evidence,
phase point-budget rejection, and command queue exhaustion. Retain schema
validation and Rust/JavaScript roundtrip artifacts for full-width scalar
boundaries, SnapshotId, every root envelope and enum variant, duplicate/unknown
properties, negative zero, forbidden null, and rejected noncanonical values.

### WebSocket disconnect and resync

Retain the exact revision and a trace that identifies committed projection
state, the notification sequence before loss, the induced slow-client gap or
disconnect, the subsequent HTTP GET, and its `ViewReceipt`. The trace must show
that ingest continued and that delivery sequence never entered semantic state.

### Browser

Retain the exact revision, browser name/version, viewport sizes, served asset
identity, and the two distinct dynamic profile fixtures/corpus. Preserve
screenshots or an equivalent trace proving simultaneous facets, truthful axes
and units, missing-versus-zero, stable identity through resize/zoom, and a
visible disconnected state without synthetic data.

### End to end

Retain the identities of authenticated captured datagrams/corpus and resulting
session, the committed projection database, process configuration, HTTP and
WebSocket traces, browser artifact, commands/procedures, environment, result,
and time. The receipt must connect those artifacts rather than substituting
independent synthetic endpoint fixtures.

These browser, disconnect/resync, and capture-to-UI receipts are absent at the
inspected snapshot. The Open gates table points to the GitHub Issues that own
the remaining live work.
