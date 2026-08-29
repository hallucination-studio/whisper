---
status: accepted
---

# Commit complete Demo ingest in one transaction

The Demo Slice publishes committed native-coordinate CSI but has no independent
Timeline or Engine step that justifies the larger persistence contract's raw
fact and semantic transaction split. A split would expose crash and recovery
states that the bounded Demo neither needs nor accepts, while decoding before
replay authority must not create side effects. Therefore authenticated body
decoding produces only a pure candidate, and one `BEGIN IMMEDIATE` atomically
commits replay admission, exact packet, optional capability and CSI, Capture
Session cursor, and one Store watermark advance. Only that committed watermark
may be published. Exact effects and rejects are owned by the
[Demo Slice v1 specification](../specs/demo-slice-v1.md).
