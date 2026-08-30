# Documentation authority router

Start here for every documentation question. First identify the kind of claim,
then follow the canonical owner below. A document may link to another kind, but
must not redefine material owned there.

## Authority by claim

| Question | Canonical authority | Rule |
| --- | --- | --- |
| What does a domain term mean? | The context glossary selected by [`../CONTEXT-MAP.md`](../CONTEXT-MAP.md) | `CONTEXT.md` files contain terminology only. |
| Which module owns a responsibility, where is a seam, or which invariant constrains the design? | [Architecture index](architecture/README.md) | Architecture records only non-discoverable ownership, seams, and invariants. Code remains the source for implementation facts. |
| Why was a consequential choice made? | [ADR index](adr/README.md) | Use an ADR only when the choice is hard to reverse, surprising without context, and the result of a real trade-off. ADRs preserve the decision and rationale; they never own normative byte layouts or behavior contracts. |
| What exact bytes, protocol, schema, or behavior are accepted? | [Versioned specification index](specs/README.md) | Specifications own normative contracts and accepted targets, including cross-context contracts. |
| What does the repository implement now? | [Host code](../src/) with [integration tests](../tests/), or [firmware code](../firmware/esp32-native-frame/main/) with [firmware tests](../firmware/esp32-native-frame/tests/) | An implemented fact requires both implementation and behavior-focused test source at an identified revision. |
| Was a test or operational gate actually run? | [Evidence index](evidence/README.md) | Test source is not executed evidence. A receipt identifies the revision, environment or artifact, command or procedure, result, and time needed to interpret it. |
| How is a build, provisioning, flash, or live check performed? | [Operations index](operations/README.md) | A procedure is not proof that it was executed. |
| What remains open or blocked? | [GitHub Issues](agents/issue-tracker.md) | Issues own open work, open decisions, and blockers. |
| What may be pursued later? | [Roadmap](ROADMAP.md) | The roadmap owns future intent, not accepted contracts or current behavior. |
| Where did an external fact come from? | [References index](references/README.md) | References preserve provenance and do not become normative merely by being cited. |

If a canonical destination does not yet exist, open or update a GitHub issue;
do not place the claim in the nearest convenient document.

## Migration state

The legacy monolith retirement is complete. The root architecture monolith was
deleted after its compact authority index moved into [`AGENTS.md`](../AGENTS.md).
This document retains the detailed routing, maturity vocabulary, and conflict
rules. [`../IMPLEMENTATION_PLAN.md`](../IMPLEMENTATION_PLAN.md) remains a thin
compatibility entry point; it owns no architecture, behavior contracts,
implementation facts, plans, status, decisions, blockers, or evidence.

[GitHub Issues](agents/issue-tracker.md) are the single live authority for open
work, open decisions, blockers, dependencies, and evidence gaps. A historical
`PASS` or status statement is not executed evidence, and plan status is not live
state.

The completed chapter-by-chapter routing is preserved in the
[legacy migration ledger](migration/legacy-ledger.md) as a historical record.

## Topic routes

Use these routes after selecting the authority kind above. Each link goes to a
concrete owner; Issues provide live gap and decision state rather than serving
as a substitute document.

| Topic | Concrete owners |
| --- | --- |
| Bounded ESP32-S3-to-Chrome Demo Slice | [Demo Slice v1 specification](specs/demo-slice-v1.md), [architecture](architecture/demo-slice.md), and [ADRs 0016](adr/0016-new-capture-session-per-serve.md), [0017](adr/0017-atomic-capture-ingest.md), and [0018](adr/0018-independent-host-supervisor.md). This route is first-applicable for Store, Capture Session, atomic capture ingest, canonical API subset, polling, and demo-smoke questions. |
| Firmware and native-frame | [Specification](specs/native-frame-v1.md), [architecture](architecture/firmware-native-frame.md), [evidence](evidence/firmware.md), [operations](operations/firmware.md), and [provenance](references/native-frame.md) |
| Shared host configuration and Managed store lifecycle, plus deferred Semantic Session persistence | [Specification](specs/persistence-v1.md), [architecture](architecture/host-persistence.md), [local-namespace rationale](adr/0013-trust-program-1-local-store-namespace.md), [Semantic Store rationale](adr/0003-sqlite-authoritative-session-store.md), and [evidence](evidence/host-persistence.md) |
| Shared Capture Profile and native observation contract, plus deferred Timeline, world runtime, and evaluation | [Temporal/world specification](specs/temporal-world-v1.md), [evaluation specification](specs/evaluation-v1.md), [architecture](architecture/world-runtime.md), [ADR rationale](adr/0002-engine-single-writer.md), and [evidence](evidence/world-runtime.md) |
| Deferred full query, API, WebSocket, and diagnostic UI | [Specification](specs/api-ui-v1.md), [architecture](architecture/query-runtime.md), and [evidence](evidence/query-ui.md) |

## Maturity vocabulary

- **Implemented fact**: behavior present in code at an identified revision and
  covered by behavior-focused test source. Prose or untested code does not
  establish an implemented fact.
- **Test source**: checked-in code or fixtures that define a check. Its presence
  does not prove the check was executed or passed.
- **Executed evidence**: an immutable receipt for an actual run against an
  identified revision, environment, or artifact. A status sentence is not a
  receipt.
- **Accepted target**: a normative requirement in an identified versioned
  specification. It may intentionally be absent from the current implementation.
- **WIP**: unaccepted or uncommitted work under development. WIP is never
  as-built authority or an implemented fact.
- **Open work**: a concrete incomplete deliverable tracked by a GitHub issue.
- **Open decision**: an unresolved choice tracked by a GitHub issue; it is not an
  ADR until decided.
- **Blocker**: an issue whose unresolved condition prevents another issue or
  acceptance gate from completing.
- **Future**: non-accepted direction recorded in a roadmap.
- **Authority conflict**: two canonical authorities of the same kind make
  incompatible claims for the same scope and version, or a document claims
  authority reserved for another kind. An expected gap between an accepted
  target and current implementation is not an authority conflict.

## Conflict handling

When documents disagree, classify each claim by authority kind and version
before changing either one. Report a same-kind authority conflict in a GitHub
issue. Track an implementation-to-target gap as open work or a blocker. Never
resolve ambiguity by presenting WIP, a roadmap, or an unexecuted test as current
behavior or evidence.

## Representative trace

For example, ask what "Link" means. Root [`AGENTS.md`](../AGENTS.md) sends the
reader here; this router assigns terminology to a context glossary;
[`../CONTEXT-MAP.md`](../CONTEXT-MAP.md) selects the Rust host context; and
[`../src/CONTEXT.md`](../src/CONTEXT.md) is the one canonical owner. The answer's
authority kind is glossary. Behavior or status maturity is not applicable
because a term definition asserts no implementation, target, or run state.
