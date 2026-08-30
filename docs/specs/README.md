# Versioned specifications

Load a specification for accepted byte, schema, API, or behavior contracts.
Every listed document is an accepted target, not proof of implementation or
execution.

| Trigger | Owner |
| --- | --- |
| Store, per-serve Capture Session, atomic capture ingest, topology/signals/live subset, polling fallback, or demo-smoke | [Demo Slice v2](demo-slice-v2.md), first-applicable for the bounded delivery path |
| Native-frame bytes, authentication, capability, provisioning, CSI validity, sender behavior, or host admission | [Native-frame v1](native-frame-v1.md) |
| Shared host configuration identity, Managed store lifecycle, or deferred Semantic Session SQLite, recovery, retention, and faithful replay input | [Host persistence v1](persistence-v1.md); the Demo imports only the named shared subset |
| Capture Profile identity, native-coordinate `CsiObservation`, or deferred time, sequence, windows, conditioning, statistical baseline, world aggregation, Engine, and semantic replay | [Temporal world v1](temporal-world-v1.md); the Demo imports only the named Profile and observation subset |
| Deferred calibration, data splits, leakage, semantic evaluation, or runtime evaluation | [Temporal world evaluation v1](evaluation-v1.md) |
| Full query projections, HTTP, WebSocket, SignalView, JSON DTOs, or diagnostic UI | [Query, API, WebSocket, and diagnostic UI v1](api-ui-v1.md) and its [JSON Schema 2020-12 artifact](schemas/api-ui-v1.schema.json); the Demo imports only its named subset |
| Deferred Semantic Program / Program 1 fixture cardinality, corpus input lineage, typed executed-claim ancestry, E2E classification, or composed physical-to-browser acceptance | [Single-sensor development E2E v1](development-e2e-v1.md) and its [Program 1 JSON Schema 2020-12 artifact](schemas/development-e2e-v1.schema.json) |
