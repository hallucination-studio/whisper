# Documentation authority router

Select the kind of claim before selecting a document. The accepted RF world
model is one architecture with one implementation graph; the retired Demo and
Semantic Program are not alternative delivery routes.

| Claim | Canonical owner |
| --- | --- |
| Domain terminology | [Context map](../CONTEXT-MAP.md), then its selected glossary |
| Responsibility, dependency direction, seams and invariants | [Architecture index](architecture/README.md) |
| Accepted bytes, schema, API and behavior | [Specification index](specs/README.md) |
| Consequential decision and trade-off | [ADR index](adr/README.md) |
| Current implementation | [Host source](../src/), [tests](../tests/), firmware source and tests |
| Executed test or operational evidence | [Evidence index](evidence/README.md) |
| Build, provisioning, capture and live procedures | [Operations index](operations/README.md) |
| Open work, dependencies, blockers and completion | [GitHub Issues](agents/issue-tracker.md) |
| Later intent outside the accepted first room | [Roadmap](ROADMAP.md) |
| External provenance | [References](references/README.md) |
| Ticket work/review model allocation | [Execution rules](agents/ticket-execution.md), then each ticket's frozen assignments |

## Current routes

- [RF world-model v1](specs/rf-world-model-v1.md) defines the accepted phone,
  heterogeneous measurement, joint state, training, runtime and evaluation
  target. Its [architecture](architecture/rf-world-model.md) owns the seams.
- [Native-frame v1](specs/native-frame-v1.md) and its
  [firmware architecture](architecture/firmware-native-frame.md) remain the
  unchanged external device input contract. Pinned historical references inside
  that contract preserve the existing provisioning clauses; they do not revive
  the old Host program or require its completion.
- [ADR 0020](adr/0020-rf-world-model-hard-rebuild.md) determines the hard rebuild:
  removed Host contracts have no compatibility entry point, migration graph,
  schema importer or parallel production implementation.
- [Spec #163](https://github.com/hallucination-studio/whisper/issues/163) and its
  native child/blocking graph own execution. Old closed tickets are not carried
  forward as prerequisites or proof of the new target.

The user-frozen final design file is unchanged; its digest is recorded in the
new specification. This router does not copy that plan or create a competing
roadmap for the accepted work.

## Maturity and conflicts

An **accepted target** can be absent from code. An **implemented fact** needs
identified source and behavior tests. **Test source** does not establish an
executed result; an **executed receipt** identifies revision, environment,
command/procedure, time and outcome. **WIP** and future intent are neither.

Issues own unfinished work and evidence gaps. A design-review pass permits
implementation, not a claim of RF accuracy. Old evidence remains bounded to its
original revision and scope; closing an abandoned ticket does not complete it.

For conflicting claims, compare authority kind and scope. New target versus
old implementation is an implementation gap, not permission to describe the
new behavior as shipped. Two conflicting accepted targets require one explicit
decision, not a compatibility layer. Historical deleted documents remain
available at their Git revision, not as live routing stubs.
