# 第一版本实现计划

- 状态：已确认，待执行
- 范围：事实内核、持久化与 replay、最小 RF World Model、查询与动态可视化
- 执行者：按工作包委托 Luna Max
- 验收者：本线程；只审阅、运行检查、决定通过或退回，不直接修改实现

## 1. 不可违反的执行约束

### 1.1 架构文档只读

`ARCHITECTURE.md` 是本轮实现的受保护合同，当前 SHA-256 为：

```text
e03eccca3f01d5c3e530d5237964b2bbde219703a3c849b6b9b0e8f6b7782e08
```

每个执行工作包开始和结束时都必须运行：

```sh
shasum -a 256 ARCHITECTURE.md
shasum -a 256 IMPLEMENTATION_PLAN.md
```

规则：

- 执行 agent 不得修改、格式化、重命名、移动或删除 `ARCHITECTURE.md`。
- 执行 agent 不得修改本计划；只有验收线程可以更新工作包状态。
- 每个工作包下发时记录本计划摘要，结束时必须与开始值相同。
- 架构摘要变化时，当前工作包直接判定失败，不先讨论实现质量。
- 实现发现架构矛盾或缺口时立即停止，只提交问题、影响范围和最小选项；不得把架构修改混入代码 diff。
- 只有用户明确批准的新任务才能修改架构；批准前不得用实现反向定义事实、身份、时间、坐标或神经模型权限。

### 1.2 第一版本范围

第一版本只实现：

```text
UDP/session bytes
    -> typed dynamic CSI
    -> timeline + conditioning
    -> BaselineEstimator
    -> WorldSnapshot (RF World Model state)
    -> HTTP/WS + one 2D diagnostic page
```

第一版本完成 [架构准入测试 1—34](ARCHITECTURE.md#22-开发准入测试) 的功能合同。它是功能开发基线，不声称已经完成后续 30 分钟吞吐、CPU candidate 或神经模型演化门禁。

明确不实现：

- `candidate.rs`、`CandidateInput`、AR(1)、learn/evaluate/select/rollback shadow；
- RF 预训练/部署神经模型、frozen encoder、GRU、Transformer、RSSM、Perceiver、MoT 或 ML backend；
- Intel 5300 真实 decoder/transport；只保留 `3 × 3 × 30` 内存兼容测试；
- 通用 modality/codec/decoder/storage trait、神经模型/adapter/packer/backend registry；
- 数据库、多 crate workspace、插件、微服务、通用 event bus；
- presence、人数、姿态、手势、生命体征、三维重建或 synthetic world；
- 固定 RF tensor、公共 token schema、统一 padding 网格；
- 长期历史索引、多分辨率 cache、state revision 或告警系统。

### 1.3 最小实现原则

- 一个 Rust package，library + binary；不建 workspace。
- 默认使用具体类型和 `pub(crate)`；没有真实外部消费者时不稳定公共 SDK。
- 一个 ingest owner 顺序拥有 `Timeline`、`BaselineEstimator` 和当前 `WorldSnapshot`。
- 原始 datagram 是唯一事实源；不写第二份 decoded CSI 日志。
- 外部输入失败返回分类 `Result`；只有被检测到的程序不变量可以 panic。
- 不使用 `unsafe`。
- 新依赖必须服务当前工作包；不得为以后预装模型、数据库或前端框架。
- 初始依赖上限为：序列化/TOML、一个 CBOR 实现、SHA-256、CRC32、错误派生和受支持目标上的 mimalloc；运行时阶段再加入 Tokio/结构化日志，HTTP 阶段再加入一个 server stack。超出必须先由验收线程批准。
- CBOR、digest 与 CRC 不自行发明通用库；具体编码必须留下固定 bytes fixture。
- 前端使用原生 HTML/CSS/JavaScript 与 Canvas/SVG；不引入 Node 构建链和组件框架。

## 2. Luna Max 执行与本线程验收协议

每个工作包使用一个新的 Luna Max 执行 agent。共享工作区一次只允许一个写入型工作包处于运行状态；可以并行委托其他 Luna Max 做只读审阅，但不得让两个 agent 同时修改相同或相邻合同文件。

### 2.1 下发给执行 agent 的固定指令

每次任务必须包含：

1. 阅读完整 `ARCHITECTURE.md` 和本计划；
2. 声明唯一文件所有权；只修改工作包列出的文件；
3. 不修改 `ARCHITECTURE.md` 和本计划；
4. 不回滚、不覆盖其他 agent 或用户的改动；
5. 不增加工作包未要求的兼容层、trait、feature、依赖或公共 API；
6. 先实现行为和最小测试，再运行工作包检查；
7. 返回 changed files、行为摘要、检查结果、未完成项和任何架构疑问；
8. 不 commit、不改写 git 历史。

### 2.2 本线程的固定验收步骤

每个工作包完成后，本线程只做以下工作：

1. 验证 `ARCHITECTURE.md` SHA-256 未变化；
2. 验证本计划摘要与工作包开始值相同，检查 `git status` 和 diff，拒绝越权文件与无关重构；
3. 检查依赖方向、事实边界、动态坐标、错误语义和确定性；
4. 运行该工作包检查和当前全部回归测试；
5. 委托另一名 Luna Max 做只读对抗审阅；
6. 判定 `PASS` 或列出 blocker，交回原执行 agent 修复；
7. 只有当前 gate 通过后才下发下一工作包。

本线程不直接修代码。若某项需要修改架构或扩大范围，停止执行并请求用户决定。

## 3. 阶段一：事实内核

目标：配置能够描述多个 ESP32/link/profile，真实 ADR-018 bytes 能严格解码为保留原生坐标的 `CsiObservation`。

### 工作包 1.1：package、domain 与有效配置

所有权：

```text
Cargo.toml
Cargo.lock
src/lib.rs
src/main.rs
src/domain/**
src/config.rs
tests/config_*.rs
tests/domain_*.rs
tests/fixtures/config/**
```

实现：

- 建立单 package、edition 2024、`rust-version = "1.91"` 和 workspace lint 等价的 package lint；受支持目标的 application binary 使用 mimalloc；
- 实现身份 newtype、`SessionTime`/interval/time quality；
- 实现 `CsiPath`、`CsiSampleAxis`、`CsiLayout`、`IqSample`、`CsiCapture::try_new`；
- 实现 `CaptureProfile`、canonical descriptor digest、`ProfileCatalog::intern`；
- 实现 `HardwareKind`、Registry、route、source contract、channel policy 和全量配置校验；第一版本配置覆盖 capture/session/window/quality/baseline/view/server/performance 所需字段，candidate mode 只接受 `disabled`；
- 实现最小 `check-config` CLI；
- 定义 session/estimator 后续确实需要的稳定 domain/world value：`Knowledge`、baseline command/snapshot、world/evidence 使用的 ID 与 transport-neutral envelope；这里只定义不变量和构造校验，不实现 estimator 行为或 future modality 空 variant。

必测：

- 空 path/axis、坐标重复、长度不符、checked multiplication overflow；
- 同 ID descriptor 冲突；
- route/peer/node/link 歧义、未知硬件和 channel policy 冲突；
- 相同 `String` 不能跨不同 ID 类型混传；
- 内存构造 Intel `TxRx 3 × 3 × 30`，共 270 个不同 native coordinate，可通过 domain 构造；
- canonical profile fixture bytes 与 SHA-256 固定。

禁止：

- Intel decoder、adapter trait、任意 rank tensor、dataset ID 路由；
- Tokio、HTTP、session I/O、baseline；
- 为 future neural model 暴露 latent/token 类型。

### 工作包 1.2：CapturedPacket 与唯一 ESP32 dispatcher

前置：工作包 1.1 PASS。

所有权：

```text
src/capture.rs
src/esp32.rs
src/lib.rs                 仅增加模块声明
tests/esp32_*.rs
tests/fixtures/esp32/**
```

实现：

- `CapturedPacket` 只保存 session/record/time/peer/wire/bytes，不打开 socket；
- 实现 ADR-018/ADR-110 唯一 dispatcher 和 sibling magic 分类；
- 严格检查 header、动态 path/sample count、payload、trailing bytes 和上限；
- 显式完成 `[imaginary, real] -> q/i` 映射；
- ADR path 只映射 `RawPathOrdinal`，sample 只映射 `OpaqueSampleOrdinal`；
- 按 route capability 处理 bytes 18..19、first-word invalid 和 inference eligibility；
- resolve 到 `SensorId`、`RadioLinkId` 和 `CaptureProfileId`，未知来源只返回分类拒绝。

必测：

- 真实 64/128/256 等动态长度 fixtures；这些只是 fixture，不是领域常量；
- 每个合法 datagram 的所有截断前缀都返回错误且不 panic；
- 零 count、超限、溢出、长度不符和 trailing bytes；
- unsupported sibling 与 malformed 分类不同；
- 不同 peer 的相同 node、未 provision transmitter、channel mismatch；
- 未声明 HE tagging 不解释扩展 bytes；C6 缺 validity 时 inference-ineligible；
- 同 count、不同 LTF/validity descriptor 得到不同 profile ID。

### 阶段一 Gate

必须通过架构测试 1—4、6、13—16、33 的 domain 部分，以及：

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
```

验收线程额外扫描 domain/session/API/UI 不存在权威固定 `56`、固定 `64` 或固定 snapshot 数；fixture 名称和测试数据不算领域合同。

## 4. 阶段二：持久化、capture 与 replay

目标：先持久化 raw packet，再解码；session 可严格读取、检测损坏、恢复 crash tail，并从相同 bytes 重放。

### 工作包 2.1：session container

前置：阶段一 PASS。

所有权：

```text
src/session.rs
src/lib.rs                 仅增加模块声明
Cargo.toml                 只增加当前 session container 所需 CRC/编码依赖
Cargo.lock                 只接受上述依赖的机械更新
tests/session_*.rs
tests/fixtures/session/**
```

实现：

- file header、named-field CBOR manifest 和 length+CRC record；
- `SessionRecord` 的 packet、baseline command、timeline advance、closed；
- 严格 `record_seq`、monotonic `at`、schema、长度上限和 trailing data 校验；
- writer append/flush/sync 与 `durable_through_record_seq`；
- reader roundtrip、中段 CRC 失败、截断尾部 recovery-seal；
- `Closed`、rotation/recovery 所需的 record-boundary primitive；
- 最小 retention 只删除最旧的 closed/recovery-sealed session，永不删除 active session，不建数据库/refcount/artifact GC；
- 使用标准库 advisory file lock；不建 sentinel、refcount database 或通用 object store；
- manifest 中 future shadow selection 字段保持 `None`，第一版本不实现 artifact 导入/选择/GC。

必测：

- header/manifest/record 固定 bytes fixture；
- config/build/decoder/conditioning/algorithm pin roundtrip；
- 长度超限在分配前失败；
- CRC 中段损坏带 offset 失败；
- 任意尾部截断只恢复完整前缀并标记 read-only；
- record sequence 重复、跳号、倒退时间和 Closed 后 append 被拒绝；
- sync/append 故障不产生可发布状态。

### 工作包 2.2：capture/replay 应用壳

前置：工作包 2.1 PASS。

所有权：

```text
src/app.rs
src/main.rs
src/lib.rs                 仅增加模块声明/最小启动 API
Cargo.toml                 只增加已批准的 Tokio/结构化日志依赖
Cargo.lock                 只接受上述依赖的机械更新
tests/app_capture_*.rs
tests/app_replay_*.rs
```

实现：

- `capture | replay | check-config` CLI；
- app 独占 socket、文件、任务和 shutdown，领域模块不读取系统状态；
- UDP receive buffer 使用 65,535 bytes，完整接收后再按业务上限拒绝；
- ingest 总序为 assign record/time → session append → decode/resolve；
- raw 已 durable 后，unknown/malformed 才记录分类拒绝并继续；
- replay 使用 manifest pin 和同一个 ESP32 decoder；第一版本此时输出 typed decode/health 流，阶段三接入相同 Engine 后升级为 semantic replay；
- graceful shutdown 写 `Closed` 并 sync；不建 HTTP、actor graph 或 writer task 拆分。

必测：

- 超大 UDP datagram 被完整接收后明确拒绝，不伪装成截断包；
- append 失败后 decoder/状态更新未发生；
- raw packet live/replay 解码结果相同；
- unknown route 和 malformed packet 已记录但不进入推理输入；
- runtime lock 冲突明确拒绝；
- 关闭和 crash-recovered session 均能只读 replay。

### 阶段二 Gate

必须通过架构测试 5、25—27 中当前可实现部分，以及阶段一全部回归。相同真实 packet corpus 的 session roundtrip 必须保持原始 bytes、peer、record sequence 和时间不变。

## 5. 阶段三：最小 RF World Model

目标：把动态 CSI 变成可回放的 per-link prediction/assessment/decision，并保守聚合为房间级世界状态。

### 工作包 3.1：Timeline

所有权：

```text
src/timeline.rs
src/lib.rs                 仅增加模块声明
tests/timeline_*.rs
```

实现 sequence source、HostEpoch、profile partition、wrap/gap/duplicate/reorder/restart、active watermark、固定非重叠窗口、missing span 和 `TimelineAdvance`。所有时间由参数传入，不读取墙钟。

必测架构测试 7—12；特别覆盖 A/B/A profile 交错、inactive stream、半开窗口边界和 replay advance。

### 工作包 3.2：Conditioning

前置：工作包 3.1 PASS。

所有权：

```text
src/conditioning.rs
src/lib.rs                 仅增加模块声明
tests/conditioning_*.rs
```

实现 per-native-coordinate `ln(1+hypot(i,q)*scale)`、actual-delta temporal slope、质量/exclusion 和 `ConditioningReceipt`。不插值、不 padding、不使用 phase 推理。

必测不同 path/sample 数、missing/invalid/non-finite/零或倒退时间、稳定 coordinate 排序和 receipt record range。

### 工作包 3.3：BaselineEstimator 与 WorldSnapshot

前置：工作包 3.2 PASS。

所有权：

```text
src/estimator.rs
src/domain/world.rs        只补充阶段三已使用的稳定值
src/lib.rs                 仅增加模块声明
tests/estimator_*.rs
```

实现：

- per-link/profile/path/native-coordinate Welford learning；
- mature/commit/active/frozen/stale lifecycle；
- pre-update EW prediction、standardized residual、nearest-rank score；
- `rf_dynamics` 使用 conditioning 的 temporal absolute slope 做 nearest-rank 分位数，单位固定为 log-amplitude/second，只作诊断，不参与 `Stable/Changing` gate；
- 完整 `LinkQuality` eligibility conjunction：frame count、ready-coordinate coverage、gap ratio、receive jitter、finite/ordered values/time、time source 以及 resolved/compatible source/link/profile；每个实测值和拒绝原因进入 receipt；
- predict → score → gate → optional update；
- `BaselineRevision` 与 `BaselineStateSequence`；
- profile 先归约到 physical link，再归约到 space；
- `Stable | Changing | Unknown(reason)`、diagnostics、contribution/exclusion；
- `CoordinateEvidence` 和 `LinkStepEvidence` 作为 `EstimatorStep` 的可审计输出；第一版本没有消费者，不提前构造 `CandidateInput`。

必测架构测试 17—23，包括 baseline poisoning、gap exposure、rotation 后 adaptation armed、同一 link 多 profile 只算一个 coverage link；逐项 quality predicate 失败都必须拒绝更新，`rf_dynamics` 的单位/nearest-rank/determinism 有独立测试。

### 工作包 3.4：Engine 与完整 faithful replay

前置：工作包 3.3 PASS。

所有权：

```text
src/engine.rs
src/app.rs                 只接入 Engine/replay/shutdown
src/session.rs             只接入已定义 baseline command/snapshot
src/lib.rs                 仅增加模块声明/最小启动 API
tests/engine_*.rs
tests/replay_*.rs
```

实现唯一 world 写入路径；live/replay 共享 decoder、registry、timeline、conditioning、estimator 和 engine；Engine 只返回包含 snapshot 与 `LinkStepEvidence` 的具体内部 `EngineOutput`，由 `app.rs` 更新 snapshot-pinned read store，Engine 不依赖 view/read store；第一版本不实现 `CandidateInput`/candidate；baseline command 先记录并 durable 再执行；`finish`、rotation 和 shutdown 完成 snapshot handoff。

必测：

- 架构测试 20、22—24；
- 两 sensors × 两 profiles 同一 window 只产生一个 snapshot；
- 相同 session/build/config 的 live 与 faithful replay typed semantic projection 相等；
- HTTP/delivery/运行耗时不进入 snapshot；
- `Engine` 保留具体 `EstimatorError`，证据不足返回 `Unknown` 而不是 `Err`。

### 阶段三 Gate

必须通过架构测试 7—24、阶段一/二全部回归，以及完整格式、Clippy、test、rustdoc 检查。

## 6. 阶段四：查询与动态可视化

目标：在不改变事实、统计估计与 RF World Model 语义的前提下，查询多个动态 profile，并通过一页二维诊断 UI 看清信号、时间、世界状态和 baseline。

### 工作包 4.1：View 与 bounded read store projection

所有权：

```text
src/view.rs
src/app.rs                 仅接入 bounded immutable read store
src/lib.rs                 仅增加模块声明
tests/view_*.rs
```

实现 `SignalQuery`、per-stream/profile `SignalTile`、native axis、missing span、snapshot evidence 和 viewport 聚合。I/Q/amplitude 支持 min/max/mean/RMS/count；phase 超预算返回明确拒绝。

必测架构测试 28—30、33 的 view 部分；不同长度同时查询时不得合并、取模复制或补零。

### 工作包 4.2：HTTP、WebSocket 与运行时组合

前置：工作包 4.1 PASS。

所有权：

```text
src/server.rs
src/app.rs                 只接入 server/command queue/shutdown
src/main.rs                只接入最终 CLI
src/lib.rs                 仅增加模块声明/启动 API
Cargo.toml                 只增加一个已批准的 HTTP/WebSocket server stack
Cargo.lock                 只接受上述依赖的机械更新
tests/server_*.rs
```

实现架构列出的 topology/signals/timeline/world/evidence/baseline endpoint、baseline command、有界 WebSocket 通知和 recent-range 错误。server 只读 immutable store 或发送有序 command，不持有 `&mut Engine`。

必测非法 query 4xx、typed unknown/empty、`RangeUnavailable`、慢客户端不反压 ingest、command queue 满返回 503、delivery sequence 不进入 semantic snapshot。

### 工作包 4.3：一页二维诊断 UI

前置：工作包 4.2 PASS；执行 agent 必须先读取并遵守 frontend-design skill。

所有权：

```text
web/**
src/server.rs              只允许最小静态资源路由
tests/web_*.rs             仅轻量静态合同检查
```

实现：

- topology 与 link/profile selector；
- 按 stream/profile 分面的 time × native-coordinate 信号图；
- sequence/gap/restart/rate/jitter/baseline command timeline；
- predicted/observed、deviation、RF dynamics、quality；
- space `Stable | Changing | UNKNOWN`、contributions/exclusions；
- baseline lifecycle/maturity/revision/decision；
- disconnected 明确显示，不创建 synthetic data。

UI 使用 API 返回的原生语义：`OpaqueSampleOrdinal` 不称 tone/MHz/subcarrier；没有几何不画空间热图；没有人体标签不画人体。

### 阶段四 Gate

必须通过架构测试 25—34 和前面全部回归。本线程另外启动本地服务，用至少两个不同动态长度/profile 的 fixture 做浏览器验收：

- 两个 profile 同时可见，坐标轴和单位正确；
- missing 与零值视觉上可区分；
- resize/zoom 不改变物理身份；
-断开后显示 disconnected；
- 页面没有 synthetic、默认首节点、取模复制或固定 RF tensor 路径。

## 7. 第一版本最终验收

### 7.1 自动检查

```sh
shasum -a 256 ARCHITECTURE.md
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
```

必须确认：

- 架构摘要仍为 `e03eccca3f01d5c3e530d5237964b2bbde219703a3c849b6b9b0e8f6b7782e08`；
- 架构测试 1—34 有逐项对应的 runnable test 或明确端到端验收；
- 没有 `unsafe`、未授权依赖、future feature flag、空 trait 或第二套 parser；
- domain/session/API/UI 没有权威固定 RF shape；
- 没有 `candidate.rs`、ML runtime、数据库或第二事实源；
- `cargo tree` 中没有未授权的 GPU/ML/frontend/database 依赖。

### 7.2 端到端验收场景

使用至少两个 ESP32 route 和两个不同 profile/长度的真实 fixture：

1. capture 写入 closed session；
2. live 产生多个独立 stream/link belief 和单一 world snapshot sequence；
3. baseline 明确 BeginLearning/Commit 后才从 Unknown 进入 Active；
4. gap/restart/profile change 不污染另一 stream；
5. replay 产生相同 typed semantic snapshots；
6. HTTP 能查询 topology、signals、timeline、world、evidence 和 baseline；
7. WebSocket 只通知小 envelope，丢 delta 后可重新 GET；
8. UI 同时显示不同 native coordinate 数和 missing spans；
9. malformed/unknown/oversized packet 已保留 raw bytes，但没有进入 world model；
10. shutdown 后 session 可独立检查和 replay。

### 7.3 第一版本完成的含义

完成后可以声明：

- 多 ESP32 route、动态 profile 的单机 RF 事实/世界状态链路已通过真实 datagram corpus 与 runtime smoke；
- raw session 可检查、恢复和 faithful replay；
- 系统能输出可解释的 `Stable | Changing | Unknown(reason)`；
- UI 不依赖固定 tensor，能够并列显示不同 native layout。

不能声明：

- 已完成 30 分钟 `2×` 负载发布门禁；
- 已完成多台物理 ESP32 的长期 soak；
- 已实现 CPU 自监督演化或 RF 预训练/部署神经模型；
- 已支持 Intel 5300 实采或相干 mixed-device fusion；
- 已实现 presence、姿态、动作、生命体征或跨环境语义泛化。

第一版本验收通过后，是否进入多设备 soak/performance 或 CPU AR(1) 由用户另行决定，不自动继续。
