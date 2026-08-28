---
status: accepted
---

# Rotate by logical session fact bytes

Whisper limits a session by the encoded manifest and ordered fact records
attributable to that session, rather than SQLite pages, WAL growth, checkpoint
timing, or filesystem allocation. A physical metric would make rotation depend
on unrelated sessions, indexes, free-page reuse, and operational timing; the
logical metric stays deterministic across equivalent stores and faithful
replay. This choice does not cap total database or transient WAL space, so those
remain separate operational concerns. The exact accounting and rotation
behavior live in the
[host persistence v1 specification](../specs/persistence-v1.md#session-fact-bytes).
