# Documentation authority router

Start here for every documentation question. First identify the kind of claim,
then follow the canonical owner below. A document may link to another kind, but
must not redefine material owned there.

## Authority by claim

| Question | Canonical authority | Rule |
| --- | --- | --- |
| What does a domain term mean? | The context glossary selected by [`../CONTEXT-MAP.md`](../CONTEXT-MAP.md) | `CONTEXT.md` files contain terminology only. |
| Which module owns a responsibility, where is a seam, or which invariant constrains the design? | Architecture documentation | Architecture records only non-discoverable ownership, seams, and invariants. Code remains the source for implementation facts. |
| Why was a consequential choice made? | An Architecture Decision Record (ADR) | Use an ADR only when the choice is hard to reverse, surprising without context, and the result of a real trade-off. ADRs preserve the decision and rationale; they never own normative byte layouts or behavior contracts. |
| What exact bytes, protocol, schema, or behavior are accepted? | A versioned specification | Specifications own normative contracts and accepted targets, including cross-context contracts. |
| What does the repository implement now? | Code plus behavior tests at an identified revision | An implemented fact requires both implementation and behavior-focused test source. |
| Was a test or operational gate actually run? | An immutable execution receipt | Test source is not executed evidence. A receipt identifies the revision, environment or artifact, command or procedure, result, and time needed to interpret it. |
| What remains open or blocked? | [GitHub Issues](agents/issue-tracker.md) | Issues own open work, open decisions, and blockers. |
| What may be pursued later? | Roadmap documentation | Roadmaps own future intent, not accepted contracts or current behavior. |
| Where did an external fact come from? | Reference documentation | References preserve provenance and do not become normative merely by being cited. |

If a canonical destination does not yet exist, open or update a GitHub issue;
do not place the claim in the nearest convenient document.

## Migration state

Until [Issue #8](https://github.com/hallucination-studio/whisper/issues/8)
atomically retires them, [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and
[`../IMPLEMENTATION_PLAN.md`](../IMPLEMENTATION_PLAN.md) are frozen legacy
migration sources and transitional authorities for claims not yet migrated. A
claim switches to a concrete recovered owner only when the relevant recovery
ticket accepts that owner. The legacy files remain byte-unchanged until Issue #8
atomically converts them to thin pointers or indexes, so no claim becomes
ownerless during migration.

[GitHub Issues](agents/issue-tracker.md) are the single live authority for open
work, open decisions, blockers, dependencies, and evidence gaps. A historical
`PASS` or status statement is not executed evidence, and plan status is not live
state where the corresponding work is now tracked by Issues.

For an unmigrated claim, follow the recovery issue for its domain:
[#3 firmware/native-frame](https://github.com/hallucination-studio/whisper/issues/3),
[#4 timeline/world/runtime](https://github.com/hallucination-studio/whisper/issues/4),
[#5 query/API/UI](https://github.com/hallucination-studio/whisper/issues/5),
[#6 persistence](https://github.com/hallucination-studio/whisper/issues/6), or
[#7 roadmap/references](https://github.com/hallucination-studio/whisper/issues/7).
Consult the protected source only to locate and classify the claim; do not
create substitute authority prose.

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
