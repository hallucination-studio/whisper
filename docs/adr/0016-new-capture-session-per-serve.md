---
status: accepted
---

# Create a new Capture Session for every serve

The Demo Slice needs durable replay and capability continuity but does not yet
need Timeline, estimator, World, handoff, or same-semantic-session recovery.
Continuing a session after Host failure would require reconstructing and proving
those deferred semantics, while resetting replay state would permit duplicate
native frames. Therefore every `serve` creates a new non-semantic Capture
Session, while replay admission and committed capability authority remain in
the Store across Host lifetimes. This makes process failure an explicit
Demo capture boundary without turning it into a product cardinality rule or
prejudging the future Semantic Session contract. Exact behavior is owned by the
[Demo Slice v1 specification](../specs/demo-slice-v1.md).
