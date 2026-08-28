---
status: accepted
---

# Keep one sequential Engine writer

Whisper keeps Timeline, statistical baseline, and current world state behind
one synchronous Engine owned by the ingest path, instead of distributing
mutation through shared locks or independent actors. This choice concentrates
ordering and replay invariants at one interface and lets durability publish one
complete transition atomically; it gives up speculative parallel mutation and
requires measured evidence before splitting the writer. The operative behavior
is defined by [temporal world v1](../specs/temporal-world-v1.md).
