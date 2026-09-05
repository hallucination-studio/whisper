---
status: accepted
---

# Trust the Program 1 local store namespace

Current applicability: Only the trusted local namespace, cooperative lease and no-replace principles remain applicable where reused privately. Former Program 1/Demo Store schema, handles and lifecycle below do not constrain the new Store. Old-format rejection and explicit new-directory initialization follow the RF world-model contract. See [ADR 0020](0020-rf-world-model-hard-rebuild.md).

Scope: this decision governs the shared local namespace and cooperative
lifecycle used by the bounded Store and deferred Semantic Store. The bounded
delivery path has its own schema, Capture Session, and ingest contract in
[Demo Slice v2](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/specs/demo-slice-v2.md), while storage qualification and its
classification remain deferred to the Semantic Program.

## Context

Program 1 needs a fast, production-shaped demonstration on one identified Mac.
It must prevent two cooperative Whisper processes from writing concurrently,
survive Host process failure, recover SQLite WAL state, and provision a new
store without replacing an existing object. Preventing a malicious process
with the same filesystem credentials from replacing the root, database, WAL,
SHM, or lease would require a capability-relative custom VFS, a privileged
broker, or a stronger deployment boundary.

That hostile-namespace guarantee would add platform-specific storage machinery
before the board-to-browser path can inform the next modeling phase. A pathname
or advisory lock cannot honestly provide it.

## Decision

Program 1 trusts one dedicated local storage root and coordinates cooperative
Whisper processes through one lifecycle-owned lease and one writer. It accepts a
bounded current-Mac storage qualification instead of adding hostile
same-credential namespace isolation or a custom storage boundary before the
sensing path has been demonstrated. Exact root, permission, lifecycle,
publication, SQLite, recovery, and qualification behavior is owned by the
[host persistence v1 specification](https://github.com/hallucination-studio/whisper/blob/671b39d4d518c3b6bbbc173352712b7af32ee7ad/docs/specs/persistence-v1.md).

## Consequences

- The contract states only guarantees the Program 1 environment can prove.
- SQLite and ordered facts remain recovery authority after process failure.
- Store identity is not a secret, credential, attestation, or additional writer
  fence.
- Unexpected namespace mutation still fails when observed, but resistance to
  a malicious same-credential actor is not an accepted Program 1 claim.

## Alternatives considered

**Require a capability-relative custom SQLite VFS.** Rejected for Program 1
because it solves a stronger adversarial problem than the demonstration needs
and adds substantial platform-specific code before sensing feedback exists.

**Add a second database writer fence.** Rejected for Program 1 because the
retained OS lease already owns cooperative writer lifetime. A second fence
would add implementation and receipt obligations without protecting against
the explicitly out-of-scope hostile same-credential actor.
