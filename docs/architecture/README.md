# Architecture index

Load architecture for non-discoverable responsibility, dependency direction,
seam, or invariant questions. Exact behavior belongs to the linked versioned
specification, and current implementation remains discoverable from code and
behavior tests.

| Trigger | Owner |
| --- | --- |
| Bounded Store, per-serve capture, single atomic writer, query subset, polling, and browser seams | [Demo Slice architecture](demo-slice.md), first-applicable for the bounded delivery path |
| Firmware capture, sender, host admission, provisioning, and trust-boundary seams | [Firmware and native-frame architecture](firmware-native-frame.md) |
| Shared host configuration and Managed-store lifecycle, plus deferred Semantic Session persistence, transaction, recovery, and replay seams | [Host persistence architecture](host-persistence.md) |
| Deferred Timeline, conditioning, estimator, Engine, world publication, and semantic replay ownership | [Temporal world runtime architecture](world-runtime.md) |
| Deferred full query reads, command writes, server composition, WebSocket delivery, and backpressure | [Query delivery runtime architecture](query-runtime.md) |
