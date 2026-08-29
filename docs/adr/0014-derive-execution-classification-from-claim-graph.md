---
status: accepted
---

# Derive execution classification from a typed claim graph

## Context

Program 1 must distinguish immutable input content and its declared lineage
from what an identified execution actually proved. A caller-authored corpus
manifest or opaque receipt digest can preserve content lineage, but it cannot
prove that a physical board emitted the bytes or that they traversed Host,
SQLite, HTTP, WebSocket, and Chrome. Letting either artifact name an E2E class
would make classification self-issued.

The public development fixture key authenticates bytes under known test
material. It does not attest hardware origin. Program 1 also cannot delay the
demonstration for a hardware-attestation system.

## Decision

Corpus manifests own immutable content identity and input lineage only. Typed
execution claims are issued by the tool that performs each procedure and bind
identified subjects, artifacts, environment, interval, and result. A verifier
checks their evidence and ancestry and derives a Program 1 execution-result
classification. Callers, manifests, and opaque receipt bytes cannot set or
promote that classification.

Classification requires the graph inside one closed retained evidence package:
bare digests without inspectable retained artifacts cannot support a
classification. Evidence closure does not make the trusted local namespace a
hostile-filesystem security boundary. Exact package membership, locator
equality, traversal, and validation behavior is owned by the
[development E2E v1 specification](../specs/development-e2e-v1.md).

## Consequences

- The same immutable corpus can be validated without claiming that an E2E run
  occurred.
- Captured input lineage and a later `captured-corpus-e2e` execution are
  independently inspectable claims.
- Scenario generation cannot be relabeled as physical capture by changing
  caller-authored metadata.
- Program completion composes independently inspectable claims without making
  one opaque blob universal proof.

## Alternatives considered

**Put the E2E classification in the corpus manifest.** Rejected because an
input artifact cannot prove later execution and can self-assert physical
origin.

**Trust the digest of an opaque capture receipt.** Rejected because content
addressing proves only which bytes were referenced, not their type, issuer,
subjects, or supported claim.

**Require hardware attestation for physical lineage.** Deferred because the
Program 1 board and public fixture key provide no such mechanism; procedural
lineage is explicit and sufficient for this development demonstration.
