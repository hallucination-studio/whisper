# Rust Host language

This glossary defines terminology for the accepted RF world model. It does not
claim that every term already has an implemented type. Responsibilities and
contracts belong to the documentation router.

| Term | Meaning |
| --- | --- |
| Deployment | A named sensing installation grouping RF sources and one or more spatial units. |
| Sensor | A configured sensing endpoint; sensor count does not imply a mesh topology. |
| Link | An RF observation relationship, distinct from a device or processing profile. |
| Profile | The capture-semantics boundary needed to interpret native observations. |
| Raw record | An immutable admitted source fact with its original bytes and receive/capture context. |
| Raw segment | A bounded retained group of raw facts, independent of model continuity. |
| Measurement assembly | The bounded grouping of fragments belonging to one RF event. |
| Assembly close | The durable event fixing measurement membership and missing fragments. |
| Evidence block | A non-overlapping interval of new RF records that may advance formal state once. |
| Port mapping | A known relationship between streams/chains and physical antenna elements. |
| Time relation | A scoped mapping between clock domains with error and validity bounds. |
| Phase relation | A scoped RF phase-reference relationship; it is not granted by time alignment. |
| Scene snapshot | A versioned spatial coordinate system, geometry, coverage and uncertainty. |
| Calibration bundle | A versioned collection of device, geometry, RF-condition and supervision qualifications. |
| Supervision segment | A bounded set of labels with visibility, provenance, timing and spatial uncertainty. |
| Model artifact | Immutable numerical model and preprocessing content with declared schemas and bounds. |
| Model run | One fixed model/processing interpretation used for live, shadow or offline execution. |
| Input manifest | Frozen source ranges, assemblies, conditions and artifact references defining one numerical input. |
| State stream | One ordered causal chain maintaining a room's joint world state. |
| Continuity epoch | A period in which the state stream can consume its committed predecessor. |
| Key epoch | A device authentication/replay identity, distinct from a model continuity epoch. |
| Checkpoint | Self-contained committed joint state and bounded association/context references. |
| Joint state | A probability distribution over empty, one-person and unordered two-person location sets, plus overflow. |
| Overflow | An explicit state for occupancy beyond the model's supported person count. |
| Track identity | An association within observed continuity, not a person's natural or civil identity. |
| World projection | The committed, query-visible current state with run, epoch, coverage and validity. |
| Derived result log | Retained published results whose lifetime is independent of raw segment deletion. |
| Retention gap | A recorded range whose raw facts are no longer available for faithful replay or reinference. |
| Unknown | A missing or unqualified current conclusion; it is not an empty-room observation. |
| Expire | A result-bound event ending current validity without erasing later results. |
| Store | The persistent identity containing raw facts, artifacts, task state and published results. |
| Store ID | A non-secret identifier that by itself proves no authority or physical origin. |
| Managed store root | A trusted local directory and cooperative lease for one Store; not isolation from a hostile same-credential process. |
| Projection watermark | A monotonically ordered identity of a committed query-visible Store change. |
| Corpus | Sealed, provenance-preserving raw/derived training or evaluation material. |
| Host restart | A process discontinuity that creates a new live continuity epoch and requires fresh qualification. |
| Historical receipt | Retained proof of an identified past execution, limited to that revision and scope. |
