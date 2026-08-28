# Architecture chapters 19-21 destination map

This historical map records where meanings from legacy architecture chapters
19-21 were assigned before the root monolith was deleted. A row may split a
legacy subsection only where its meanings belong to different authority kinds;
the destinations remain disjoint.

## Chapter 19: CPU evolution and performance

| Legacy meaning | Destination | Authority split |
| --- | --- | --- |
| 19.1 statistical baseline estimator as the current production world path | [`temporal-world-v1.md`](../specs/temporal-world-v1.md) and [`world-runtime.md`](../architecture/world-runtime.md) | Accepted v1 behavior and ownership; not future scope |
| 19.1 separation of statistical production, CPU candidates, and offline pretraining | [`ROADMAP.md`](../ROADMAP.md) for the two future paths; temporal/world authorities for the statistical path | Current and future meanings are split by path |
| 19.1 reduced self-supervised loss does not establish semantic correctness | [`0004-research-promotion-evidence.md`](../adr/0004-research-promotion-evidence.md) and [`ROADMAP.md`](../ROADMAP.md#promotion-rule) | Decision rationale and future promotion rule |
| 19.2 native-coordinate CPU forecast candidate, training cursor, artifact, and eligibility design | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate) | Future direction and evidence gate; exact behavior waits for a promoted versioned specification |
| 19.2 frozen representation and small deployment-head alternatives | [`ROADMAP.md`](../ROADMAP.md#rf-pretraining) and [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Separate offline-pretraining and deployment directions |
| 19.3 candidate CLI, artifact/report ownership, shadow selection, retention, and runtime-lock concepts | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate) | Future lifecycle questions; implementation issues begin only after promotion |
| 19.4 positive RSS/thread limits and snapshot deadline relative to the window step | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#resource-budget) | Accepted v1 resource contract |
| 19.4 evaluation manifest, target hardware/workload identity, tail/RSS/loss reporting | [`evaluation-v1.md`](../specs/evaluation-v1.md#runtime-resource-contract) | Accepted evaluation behavior |
| 19.4 sustained packet/byte workloads, candidate/learner/shadow benchmarks, storage capacity, precision, and backend tuning | [`ROADMAP.md`](../ROADMAP.md#release-performance-and-soak) and [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Deferred release evidence versus future deployment choice |
| 19.4 ONNX Runtime facts | [`references/README.md`](../references/README.md#runtime-and-deployment-sources) | External identity and provenance only |
| 19.5 raw-ingest/statistical-world/read-view priority and no silent semantic skipping | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#resource-budget) and [`world-runtime.md`](../architecture/world-runtime.md) | Accepted v1 behavior and ownership |
| 19.5 future shadow degradation, skip, and production fallback behavior | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate) | Future behavior pending a candidate specification |
| 19.6 split/leakage and target-data reporting | [`evaluation-v1.md`](../specs/evaluation-v1.md) | Accepted evaluation contract |
| 19.6 candidate selection, rollback, held-out comparison, and semantic-ground-truth gate | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate) and [`0004-research-promotion-evidence.md`](../adr/0004-research-promotion-evidence.md) | Future gate and rationale |

## Chapter 20: pretraining, deployment, and multimodal evolution

| Legacy meaning | Destination | Authority split |
| --- | --- | --- |
| 20.1 statistical estimator alone writes the accepted v1 world state | [`temporal-world-v1.md`](../specs/temporal-world-v1.md), [`world-runtime.md`](../architecture/world-runtime.md), and [`0002-engine-single-writer.md`](../adr/0002-engine-single-writer.md) | Accepted behavior, ownership, and rationale |
| 20.1 CPU candidate/deployment and offline RF-pretraining roles | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate), [`ROADMAP.md`](../ROADMAP.md#rf-pretraining), and [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Future paths remain separate |
| 20.2 public model/project identities, papers, licenses, and runtime sources | [`references/README.md`](../references/README.md#model-and-architecture-sources) | External provenance only |
| 20.2 derived architecture experiments and ordered research sequence | [`ROADMAP.md`](../ROADMAP.md#rf-pretraining) and [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Future evidence gates, not accepted model contracts |
| 20.3 deployment state isolation, artifact compatibility, abstention, reset, and forecast surface | [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Future deployment direction; exact interface waits for promotion |
| 20.4 artifact-private offline packing and representation | [`ROADMAP.md`](../ROADMAP.md#offline-packing-and-representation) | Future representation direction and evidence gate |
| 20.4 simple causal behavior, shared core, and offline forecast/reconstruction surfaces | [`ROADMAP.md`](../ROADMAP.md#causal-behavior-and-core) | Future causal-core direction and evidence gate |
| 20.4 longer-state evidence before an RSSM responsibility split | [`ROADMAP.md`](../ROADMAP.md#rssm-candidate) | Future RSSM promotion trigger |
| 20.4 measured objective conflict before an objective-specific MoT replacement | [`ROADMAP.md`](../ROADMAP.md#mot-candidate) | Future MoT promotion trigger |
| 20.4 profiler-proven long-sequence bottleneck before a Mamba/SSM replacement | [`ROADMAP.md`](../ROADMAP.md#mamba-candidate) | Future Mamba promotion trigger |
| 20.5 representation identity, topology/alignment receipts, token budgets, and learned fusion compatibility | [`ROADMAP.md`](../ROADMAP.md#learned-multi-link-fusion) | Future learned-fusion gate |
| 20.6 accepted non-coherent per-link evidence and conservative world aggregation | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#conservative-aggregation) | Accepted v1 behavior |
| 20.6 second concrete modality and paired offline/live fusion directions | [`ROADMAP.md`](../ROADMAP.md#multimodal-sensing) | Future modality and fusion gates |
| 20.7 split-before-derivation, episode grouping, target-data disclosure, and leakage rules | [`evaluation-v1.md`](../specs/evaluation-v1.md) | Accepted evaluation contract |
| 20.7 pretrained/deployment artifact roles, compression/distillation choices, licenses, and semantic promotion | [`ROADMAP.md`](../ROADMAP.md#rf-pretraining), [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression), [`references/README.md`](../references/README.md), and [`0004-research-promotion-evidence.md`](../adr/0004-research-promotion-evidence.md) | Future choices, source provenance, and promotion rationale are disjoint |

## Chapter 21: source adjudication

| Legacy meaning | Destination | Authority split |
| --- | --- | --- |
| RuView repository identity, inspected revision, and legacy file/line provenance | [`references/README.md`](../references/README.md#inspected-ruview-source) | External source provenance |
| ESP-IDF v5.4 CSI source identity, version, and publication pin | [`native-frame.md`](../references/native-frame.md#esp-idf-v54) | Domain-source provenance |
| RF sensing, evaluation, capture-tool, and paper identities | [`references/README.md`](../references/README.md#rf-sensing-and-evaluation-sources) | External source provenance |
| ONNX Runtime and deployment-tool identities | [`references/README.md`](../references/README.md#runtime-and-deployment-sources) | External source provenance |
| Public model and architecture identities | [`references/README.md`](../references/README.md#model-and-architecture-sources) | External source provenance |
| Rejection of ADR-018/RuView wire compatibility and a second protocol path | [`0001-native-frame-authentication.md`](../adr/0001-native-frame-authentication.md) | Accepted decision rationale |
| Rejection of distributed or shared-lock semantic mutation in favor of one writer | [`0002-engine-single-writer.md`](../adr/0002-engine-single-writer.md) | Accepted decision rationale |
| Rejection of papers, available runtimes, prototypes, or lower loss as production authority | [`0004-research-promotion-evidence.md`](../adr/0004-research-promotion-evidence.md) | Accepted promotion rationale |
| Accepted firmware-to-host identity and route phases | [`native-frame-v1.md`](../specs/native-frame-v1.md#identities-and-route-phases) | Versioned behavior contract |
| Accepted dynamic capability and native-coordinate identity | [`native-frame-v1.md`](../specs/native-frame-v1.md#capability-identity) | Versioned behavior contract |
| Accepted ESP32-S3 CSI byte order, validity, and raw sample accounting | [`native-frame-v1.md`](../specs/native-frame-v1.md#csi-data-body) | Versioned behavior contract |
| Accepted event-time source, quality, and uncertainty | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#time) | Versioned behavior contract |
| Accepted native-coordinate conditioning and actual-delta transformations | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#conditioning) | Versioned behavior contract |
| Accepted baseline state keys and lifecycle | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#state-key-and-lifecycle) | Versioned behavior contract |
| Accepted baseline maturity and calibration-state construction | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#learning) | Versioned behavior contract |
| Accepted baseline eligibility, abstention, and adaptation decisions | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#eligibility-and-decisions) | Versioned behavior contract |
| Accepted conservative physical-link and space aggregation | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#conservative-aggregation) | Versioned behavior contract |
| Accepted split-before-derivation and leakage handling | [`evaluation-v1.md`](../specs/evaluation-v1.md#split-before-derivation) | Versioned evaluation contract |
| Accepted target-domain data disclosure | [`evaluation-v1.md`](../specs/evaluation-v1.md#target-domain-claims) | Versioned evaluation contract |
| Accepted target-host runtime evidence requirements | [`evaluation-v1.md`](../specs/evaluation-v1.md#runtime-resource-contract) | Versioned evaluation contract |
| Accepted typed world state and semantic evidence output | [`temporal-world-v1.md`](../specs/temporal-world-v1.md#world-state) | Versioned behavior contract |
| Runtime ownership of the sole semantic mutation path | [`world-runtime.md`](../architecture/world-runtime.md#single-writer-ownership) | Architecture ownership and invariant |
| API projections remain typed read views rather than replacement facts | [`api-ui-v1.md`](../specs/api-ui-v1.md#contract-principles) | Versioned product/API contract |
| Diagnostic UI treatment of dynamic coordinates, missing values, and semantic state | [`api-ui-v1.md`](../specs/api-ui-v1.md#diagnostic-ui) | Versioned product/UI contract |
| Evidence threshold and authority transition for any research promotion | [`ROADMAP.md`](../ROADMAP.md#promotion-rule) | Future promotion gate |
| Native-coordinate CPU forecast candidate and incumbent comparison | [`ROADMAP.md`](../ROADMAP.md#cpu-self-supervised-candidate) | Future candidate direction and evidence gate |
| Offline RF pretraining and representation experiments | [`ROADMAP.md`](../ROADMAP.md#rf-pretraining) | Future research direction and evidence gate |
| CPU deployment, compression, and distillation ordering | [`ROADMAP.md`](../ROADMAP.md#cpu-deployment-model-and-compression) | Future deployment direction and evidence gate |
| Intel 5300 acquisition opportunity | [`ROADMAP.md`](../ROADMAP.md#intel-5300-acquisition) | Future hardware direction and evidence gate |
| Clock, phase, and coherent-fusion opportunity | [`ROADMAP.md`](../ROADMAP.md#clock-phase-and-coherent-fusion) | Future calibration direction and evidence gate |
| Learned multi-link fusion opportunity | [`ROADMAP.md`](../ROADMAP.md#learned-multi-link-fusion) | Future aggregation direction and evidence gate |
| Second-modality and multimodal sensing opportunity | [`ROADMAP.md`](../ROADMAP.md#multimodal-sensing) | Future product/research direction and evidence gate |

The source identities in chapter 21 never become behavior authorities merely
because a roadmap entry cites them. A promoted capability receives a new or
extended versioned specification and bounded GitHub issue graph at that time.
