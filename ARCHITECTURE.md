# 持续学习时序 RF World Model 架构

- 状态：开发基线（Development Baseline）
- 适用范围：本仓库
- 当前采集端：ESP32 ADR-018 CSI
- 已知后续采集端：Intel 5300 CSI

本文档定义一套架构，不按 `v1`、`v2` 复制目录或分叉领域类型。“首个开发切片”只限制现在实现哪些能力，不建立一套将来需要推倒的临时架构。

## 1. 产品边界与架构结论

系统维护的是一个随时间演化、可回放、带知识边界的 RF 世界状态，而不是把 CSI 填进固定张量后调用若干互不相关的分类器。

首个开发切片必须交付：

- 多个 ESP32 同时采集，设备、链路和 baseline 互不污染；
- 同一时刻存在不同 CSI 布局时原样保存、独立建模和并列显示；
- 字节级 session 记录、确定性 replay 和损坏检测；
- 原生坐标 CSI、sequence/缺口/时间质量诊断；
- 每条链路的预测、deviation、RF dynamics 和受门控 baseline；
- 多链路到房间级 `Stable | Changing | Unknown(reason)` 的保守聚合；
- CPU-only 的实时统计预测/更新，并为 GPU 预训练、CPU 推理与小头自监督留出可验证边界；
- 一个二维诊断页面，包含 topology、signal、timeline、world 和 baseline 状态；
- HTTP 查询和小型 WebSocket 通知。

首个开发切片明确不承诺：

- presence、人数、身份、姿态、手势、跌倒、呼吸或心率；
- “人体运动概率”、OOD 概率或未经标定的 confidence；
- 相干相位融合、ToF、AoA 或三维重建；
- Intel 5300 的真实采集实现；
- foundation model、采集进程内训练神经网络主干、在线改写生产权重或自动模型晋升；
- 数据库、微服务、插件、数字孪生或 Three.js 场景。

最小内核的“持续学习”特指：在明确生命周期和污染门控下，持续更新部署现场的统计 baseline。后续神经路径仍使用同一事实与评估合同：GPU 只离线训练 RF 预训练模型并产出不可变 artifact；部署 CPU 只运行已通过效果、资源和回放门禁的部署模型。预训练模型、部署模型和生产 baseline 共享动态坐标的 forecast/evidence 语义，不要求共享 latent shape、runtime 或权重，也不在 live session 内改写当前生产状态或权重。

### 1.1 术语与命名纪律

本文只在对象确实具有可训练参数、独立 artifact 身份和推理行为时称其为“模型”。下列术语不可互换：

| 术语 | 唯一含义 | 不得指代 |
| --- | --- | --- |
| RF World Model | 整个可回放的时序 RF 世界状态系统；内部可以由统计估计器或神经模型提供证据 | 某个网络、checkpoint 或固定张量 |
| `BaselineEstimator` | live 热路径中的确定性统计估计器，维护 baseline、产生 evidence 并聚合世界状态 | 神经模型、预训练模型或 teacher |
| RF 预训练模型 | 在 sealed corpus 上离线训练、具有独立 artifact 的神经模型 | 生产权威、天然 teacher 或部署模型 |
| RF 部署模型 | 通过 holdout、完整性、CPU 预算、fallback 和 replay 门禁后获准部署的神经模型 artifact | 任何尚未准入的 candidate |
| candidate | 评估与生命周期角色；可以是 AR 算法或神经模型 artifact | 一种网络结构或公共模型基类 |
| adapter / encoder / core / head | 模型内部组件 | 默认可独立训练、部署或注册的多个模型 |
| teacher / student | 一次可选蒸馏实验中，来源 checkpoint 与目标 checkpoint 的临时角色 | 架构层、服务、模块、类型、bundle 或长期产品身份 |

“大/小”只描述规模或资源成本，不表示权威、兼容关系或必然存在的蒸馏关系。parser、conditioning recipe、threshold、fusion rule、receipt、baseline state、artifact 容器和评估报告不得笼统称为模型。代码中的统计路径统一使用 `estimator.rs`、`BaselineEstimator`、`EstimatorStep` 和 `EstimatorError`；在真实神经路径落地前，不预建 `Teacher*`、`Student*`、通用 `Model` trait 或 registry。

## 2. 不可违反的约束

### 2.1 字节事实只有一份

权威事实源是收到的 UDP datagram 及其接收上下文，记为 `CapturedPacket`。解码后的 `CsiObservation`、conditioned feature、baseline 和世界状态都是可重算的派生物。

```text
CapturedPacket                         authoritative
  └── CsiObservation                  decoder-versioned
       └── ConditionedWindow          recipe-versioned
            └── LinkBelief            baseline-versioned
                 └── WorldSnapshot    algorithm-versioned
```

不再永久保存一份重复的 decoded-frame 日志。若需要查询速度，可以建可删除的 cache；cache 不是事实源。

### 2.2 没有 canonical RF tensor

任何领域类型、session 格式、公共 API 或 UI 都不得把 `56 × 8`、`64 × N`、`256 × N` 或其他固定形状定义为权威格式。

模型内部将来可以重采样、padding 或分块，但该形状只属于一个明确的 conditioning/model 版本，不能回写原始数据，也不能泄漏为全系统契约。

### 2.3 CSI 是链路观测

CSI 描述 transmitter 到 receiver 的传播链路。进入统计估计或神经推理路径的观测必须具有 `RadioLinkId`；仅有 `node_id` 或 receiver ID 的数据不能混入别的链路。

### 2.4 未知不是错误，错误也不是未知

- 数据不足、baseline 未就绪、时间质量不足或覆盖不足产生 `Unknown(reason)`。
- malformed packet、配置冲突、CRC 损坏和存储失败产生分类错误与健康指标。
- 禁止把解析失败包装成一个“UNKNOWN observation”送入统计估计或神经推理路径。

### 2.5 时间、坐标、质量和来源不能隐式丢失

每个派生值必须能回答：来自哪个 session/record/link/profile/window，使用什么 transform 和 baseline，哪些坐标参与或被排除。

### 2.6 同一输入必须得到同一语义输出

相同 session、有序 control command、有效配置、decoder、算法和初始 baseline，在同一 build/target 上必须产生相等的 typed semantic snapshots。核心不能读取当前时间、随机数或依赖 hash-map 迭代顺序。

### 2.7 一个顺序写入者拥有世界状态

`Timeline`、`BaselineEstimator` 和当前 `WorldSnapshot` 只由 ingest task 顺序拥有，不放进全局共享写锁。HTTP、WebSocket 和 UI 只能读取 immutable view 或提交有序 command。

## 3. 端到端数据流

```text
UDP socket / session reader
          │
          ▼
CapturedPacket + total record order
          │
          ├── append session ─────────────────────────────┐
          │       append 成功才继续                        │
          ▼                                                │ replay
single ESP32 wire dispatcher                               │
          │                                                │
          ▼                                                │
Registry identity/link resolution                          │
          │                                                │
          ▼                                                │
CsiObservation: typed dynamic CSI                          │
          │                                                │
          ▼                                                │
Timeline: stream/profile/epoch/sequence/window             │
          │                                                │
          ▼                                                │
Conditioning: native-coordinate amplitude + receipt        │
          │                                                │
          ▼                                                │
per-link Predict -> Score -> Gate -> Update                │
          │                                                │
          ▼                                                │
link beliefs -> conservative space aggregation             │
          │                                                │
          ▼                                                │
immutable WorldSnapshot                                    │
          │                                                │
          ├── bounded recent read store -> HTTP queries    │
          └── latest/delta notification -> WebSocket       │
                                                           │
session reader ───────── same decoder and Engine path ─────┘
```

协议、时序、conditioning、统计估计和世界聚合是同步的普通函数/具体类型。首个切片不在每层之间放 actor 或消息总线。

## 4. 代码分层与依赖规则

### 4.1 一个 package，而不是提前拆 workspace

首个切片使用一个 Rust package（library + binary）：

```text
Cargo.toml
src/
├── lib.rs                 crate 对外只暴露启动所需的最小 API
├── main.rs                capture | replay | check-config
├── domain/
│   ├── mod.rs
│   ├── identity.rs        IDs、Deployment、Space、Sensor、RadioLink
│   ├── time.rs            SessionTime、EventTime、interval、quality
│   ├── csi.rs             CsiLayout、CsiSampleAxis、CsiCapture
│   └── world.rs           Knowledge、belief、snapshot、receipt
├── capture.rs             CapturedPacket；不打开 socket
├── config.rs              TOML、EffectiveConfig、Registry、全量校验
├── esp32.rs               唯一 ADR-018/ADR-110 dispatcher 与 resolver
├── session.rs             append/read/recovery/container
├── timeline.rs            sequence、profile、epoch、watermark、window
├── conditioning.rs        可审计的原生坐标特征
├── estimator.rs           baseline predictor、gate、space aggregation
├── candidate.rs           CPU 演化切片才增加：动态 AR(1) candidate、artifact
├── engine.rs              Timeline + BaselineEstimator；唯一 world 写入路径
├── view.rs                具体 query/result 与 viewport downsampling
├── server.rs              HTTP/WS DTO 和边界校验
└── app.rs                 socket、文件、任务、shutdown 的运行时组合
web/                       首个二维诊断页面
tests/fixtures/             真实 packet/session fixtures
```

只有文件真实变大或形成独立发布边界时才拆 crate。RuView 的多 crate 数量并没有阻止重复 parser、巨型循环和全局状态，因此 crate 数不是本项目的架构指标。

### 4.2 模块 DAG

```text
module         may depend on
────────────────────────────────────────────────────
domain         pure value/hash/serialization support only; no runtime or I/O
capture        domain
config         domain
esp32          capture + config + domain
session        capture + domain
timeline       domain
conditioning   domain + timeline
estimator      domain + conditioning
candidate      domain; frozen encoder 到来后才加 conditioning
engine         domain + timeline + conditioning + estimator
view           domain
server         domain + view
app            all modules above; composition only
main           app
```

强制规则：

- `domain` 不依赖 Tokio、HTTP、文件、ESP32、神经模型 backend 或 UI。
- `esp32` 不拥有 socket、文件或世界状态；同一协议只有一个 decoder。
- `timeline`、`conditioning`、`estimator` 不读取系统时钟、网络、配置文件或全局变量。
- `estimator` 不依赖 `server`、`view`、`session` 或 ESP32 wire 类型。
- `candidate` 不读取 session、socket 或生产 Engine；app 只按序转交 Engine 生成的 `CandidateInput`。未来 frozen encoder 通过准入后，Engine 才额外转交同 receipt 的单个 `ConditionedStream`，不能让 app 自行重算。
- `server` 不持有 `&mut Engine`，只能查询 read store 或发送 command。
- `app` 只组合和治理生命周期，不复制领域计算。
- 模块间使用具体类型；首个切片没有 `FrameDecoder`、`WorldModel`、`StorageBackend`、`ViewProjector`、`Clock` trait、registry factory 或 DI container。

箭头含义为“左侧依赖右侧”。`AlignedWindow` 只能先经过 `condition`，`BaselineEstimator` 不接收 raw window。若 view 需要近期数据，由 app 把 read-store snapshot 作为参数传入；`view` 不反向读取 session 或 Engine。

Intel 5300 真正接入后先增加具体 decoder 和一个小 enum dispatcher。只有两个真实实现暴露出相同变化轴时，才从重复代码中抽 trait。

## 5. 身份、拓扑与有效配置

### 5.1 稳定 ID

领域层使用不同 newtype，禁止用同一个 `String` 混传：

```rust
struct DeploymentId(Box<str>);
struct SpaceId(Box<str>);
struct SensorId(Box<str>);
struct TransmitterId(Box<str>);
struct RadioLinkId(Box<str>);
struct SessionId(Box<str>);
```

`HardwareKind` 至少能区分 `Esp32S3`、`Esp32C6`、`Intel5300`。首个切片加载 Intel 采集配置时返回 `UnsupportedHardware`，不能假装已经实现。

硬件类型只来自经校验的 Registry 或明确协议字段，禁止依据 CSI sample/tone 数推测。

### 5.2 CSI 属于显式链路

```rust
struct RadioLink {
    id: RadioLinkId,
    space: SpaceId,
    transmitter: TransmitterId,
    receiver: SensorId,
}
```

物理 link 不拥有固定 channel。Registry route 的 `ChannelPolicy` 定义 allowed/expected channels；packet 的实测 channel/centre frequency 只属于 `CaptureProfile`。因此合法 channel hopping 会产生多个 profile，但仍可属于同一物理 link。

首个切片不创建 Site/Building/Floor/Zone 层级。`Space` 通常是一间房；产品出现真实层级需求时，在 `Space` 外增加容器关系，不改变 CSI 路径。

### 5.3 ESP32 路由

ADR-018 的 `node_id: u8` 不是全局设备身份，而且 wire 不含 source MAC。`Registry` 用配置中的 route 将 `(node_id, expected_peer_ip)` 绑定到 `SensorId`，再依据 source contract 决定能否绑定 `RadioLinkId`：

- peer 地址匹配时按精确 route 解析；source port 不作为稳定身份；
- 没配置 peer 时，同一个 `node_id` 只能有一条无歧义 route；
- 同一 peer/node 指向多个 sensor/link 是启动错误；
- 未登记来源先写入 session，再以 `UnknownRoute` 拒绝，不能进入 baseline；
- inference-eligible route 必须登记单一 transmitter，并声明该 node 已 provision 专用源或启用固定 source-MAC filter；由于 wire 不能证明该 MAC，证据等级为 `ConfiguredUnverified`。
- 未 provision、可能混有多个 transmitter 的 packet 为 `UnresolvedSource`：首个切片只保留 raw session bytes 和 reject health，排除 recent SignalView、baseline/world，不能塞进 `unknown-transmitter-*` 假装成稳定链路。真实诊断需求出现后再增加 source-key query。
- packet/profile 的实测 channel 必须满足 link 的 `channel_policy`，否则 `RouteRadioMismatch`；channel hopping 仍可形成多个 profile，而不是改变物理 link 身份。

### 5.4 配置是 session 的输入

TOML 至少定义：

```text
deployment id
capture bind, max_datagram_bytes, socket_buffer_bytes
session directory, retention, flush policy
window width, step, allowed_lateness, inactive_after
sequence reorder_horizon, probable_restart_after
conditioning recipe and amplitude scale
quality minimum_frames, coverage, gap, jitter, time_quality
baseline learning minimum_windows/minimum_valid_exposure, EW time_constant
baseline update gate, stale_after, stable/change thresholds
performance capture max_rss, snapshot_deadline, thread limits
candidate mode: disabled | shadow; when enabled require artifact/report digests,
          max_artifact_bytes, max_learning_lag and candidate thread/RSS budgets
spaces[]
transmitters[]
sensors[]: id, hardware_kind, node_id, expected_peer_ip, firmware, adr018 capabilities
links[]: id, space, transmitter, receiver, source contract, channel policy
routes[]: peer/node/link resolution, peak_packets_per_second, maximum_valid_datagram_bytes
```

每条 route 的 peak 必须来自固件配置或实机观测再留明确余量，`maximum_valid_datagram_bytes <= max_datagram_bytes`。所有非显然数值都使用带单位的名称，并记录来源与改动影响。运行中不热更新影响推理的配置；修改后开启新 session。`EffectiveConfig` 的完整快照和 digest 写入 manifest。

## 6. 字节事实源与 session 契约

### 6.1 CapturedPacket

```rust
struct CapturedPacket {
    session_id: SessionId,
    record_seq: u64,              // 来自外层 SessionRecord
    receive_monotonic_ns: u64,    // 来自外层 SessionRecord.at
    receive_utc_ns: i64,          // 仅展示/跨文件定位
    peer: SocketAddr,
    wire_format: WireFormat,
    bytes: Box<[u8]>,
}
```

`record_seq` 是 packet 和 control command 共用的 session 总序。monotonic time 负责排序与窗口，UTC 不能参与核心顺序。

### 6.2 容器格式

首个切片固定一个简单容器，不引入数据库或通用对象仓库：

```text
file header
├── magic: "RFWSESS\0"
├── container_version: u16 little-endian
├── manifest_len: u32 little-endian
├── manifest_crc32: u32
└── manifest: named-field CBOR

record*
├── body_len: u32 little-endian
├── body_crc32: u32
└── body: named-field CBOR SessionRecord
```

```rust
struct SessionManifest {
    session_id: SessionId,
    started_utc_ns: i64,
    effective_config: EffectiveConfig,
    config_digest: [u8; 32],
    application_version: String,
    build_fingerprint: [u8; 32],
    decoder_version: String,
    conditioning_version: String,
    algorithm_version: String,
    initial_baselines: Vec<BaselineSnapshot>,
    shadow_selection: Option<ShadowSelectionPin>,
}

struct ShadowSelectionPin {
    candidate: SessionArtifactPin,
    evaluation_report: SessionArtifactPin,
}

struct SessionArtifactPin {
    kind: SessionArtifactKind,
    digest: [u8; 32],
    byte_len: u64,
}

enum SessionArtifactKind {
    Candidate,
    CandidateEvaluationReport,
}

struct SessionRecord {
    schema: u16,
    record_seq: u64,
    at: SessionTime,
    kind: SessionRecordKind,
}

enum SessionRecordKind {
    Packet {
        receive_utc_ns: i64,
        peer: SocketAddr,
        wire_format: WireFormat,
        bytes: Box<[u8]>,
    },
    BaselineCommand(TargetedBaselineCommand),
    TimelineAdvance,
    Closed,
}

struct TargetedBaselineCommand {
    target: LinkProfileKey,
    command: BaselineCommand,
}
```

`CapturedPacket` 是 decoder 使用的完整内存 view，由 record envelope + `Packet` body 组合，不在磁盘中重复序列化 total order/time。reader 必须验证 `record_seq` 从 0 开始严格递增且唯一，`at` 不倒退。

CBOR 使用 named fields 和严格 schema；不能依赖 Rust enum 的偶然内存布局。`config_digest`/`build_fingerprint` 对各自 canonical bytes 取 SHA-256，artifact/report digest 对原始文件 bytes 取 SHA-256，并随 fixed fixtures 测试；digest 用于内容身份，不替代 CRC 的损坏检测。`shadow_selection` 在 CPU 演化切片前恒为 `None`；启用后必须先校验 candidate/report 的 kind、schema、大小、report 指向 candidate 的单向 digest 关系和原始 bytes 摘要，以 temp + sync + atomic rename + directory fsync 把两者 durable 写入 `data_root/artifacts/<digest>`，再创建 manifest。candidate 不反向引用 report。它只是按摘要读取的 session attachment，不提供搜索、tag、latest 或 registry API。缺少 selection attachment 时，production semantic replay 仍继续并明确报告 `ShadowUnavailable`；只有请求 shadow replay/evaluation 才失败。当前实现只读当前 container version，第二个真实版本出现后才写迁移器。

### 6.3 写入、恢复与保留

```text
data_root/
├── sessions/
├── artifacts/<sha256-hex>
├── state/selected-shadow.cbor
└── locks/runtime.lock
```

`capture` 从读取 `selected-shadow`、验证两个 pin 到创建 session manifest，始终持有同一个 OS advisory exclusive lock。`learn-ar1`、`evaluate-candidate`、`select-shadow`、`rollback-shadow`、managed `data_root` 上的 replay/export/import，以及 retention/attachment GC 首实现也必须取得该 lock 并持有到完成；获取失败就明确拒绝，不使用会遗留 stale 状态的 create/delete sentinel。selection sidecar 使用 temp + sync + atomic rename + parent-directory fsync。这样 capture、reader、retention、离线 learner 和选择操作不会竞态；出现真实并发读取需求后才升级 shared lock/session lease。

- packet 必须 append 成功、由 writer 接管 bytes 后才能 decode 和改变世界状态。
- `BeginLearning`、`Commit`、`Freeze`、`Resume`、`ActivateSnapshot` 全部先写 session 再执行。`ActivateSnapshot` 的不可变 baseline snapshot 完整嵌入 command record，不能只引用 session 外部 revision。
- 没有 packet 但需要关闭窗口或判定 stream inactive 时，先写 `TimelineAdvance` 再调用 `Engine::advance_to`；replay 按同一记录推进，不能重新依赖墙钟。
- manifest 包含所有影响结果的配置和初始 baseline，replay 不依赖“当前磁盘配置”。
- 末尾 body 不完整表示 crash tail：恢复之前所有完整记录并明确报告 `RecoveredTruncatedTail`。
- 完整 body 的 CRC 不匹配表示中间损坏：带 byte offset 失败，不静默跳过。
- reader 在分配前检查配置硬上限 `max_manifest_bytes` 和 `max_record_bytes`；声明长度超限直接失败，不能由损坏的 `u32` 触发巨额分配。
- graceful shutdown 写 `Closed`、flush 并 sync；没有 footer 仍可扫描恢复。
- baseline snapshot 是不可变 revision 文件；当前指针用原子 rename 替换。
- retention 只删除最旧且已关闭的 session，绝不删除 active session。
- 删除 attachment 前扫描所有 retained manifest；任何 `SessionArtifactPin` 仍引用的 digest 都不能删除。首实现不维护可漂移的 refcount database。

session 同时配置 `max_session_duration` 和 `max_session_bytes`。达到任一上限时暂停新输入，并在 record boundary 执行：`append Closed -> Engine::finish -> sync old session -> 写/sync 清除 session-local stale timer 且 adaptation_armed=false 的 BaselineSnapshot -> 新 manifest 嵌入该 snapshot -> 恢复输入`。crash-recovered 文件恢复完整前缀后标记 recovery-sealed/read-only，绝不继续 append；从该前缀通过同一 finish/snapshot handoff 开启新 session。retention 可删除已 Closed 或 recovery-sealed、且不是当前 active 的文件。

`append` 只保证 bytes 已进入 writer，不等于已经抗断电。writer 维护 `durable_through_record_seq`；首个切片在发布每个 closed-window snapshot 前对其全部证据执行 `sync_data`，baseline command 也在应用前 sync。失败即停止 capture。这样已经对外发布的 semantic state 总能从持久前缀重放；若实测每窗口 sync 造成丢包，再依据 durability 指标批量化，不能暗中降低保证。

不永久保存 `CsiObservation`、window 或 snapshot 的第二份权威日志。派生 cache 随时可以删除并从 session 重建。

### 6.4 faithful replay

首个切片只实现 `faithful replay`。manifest 的 build fingerprint、decoder、conditioning 和 algorithm 必须与当前 executable 完全匹配；不匹配就拒绝，并提示使用原 build，不能靠字符串 registry 假装旧实现仍存在。

未来若确有 parser 修复或研究需要，可增加显式 `reinterpret`，用新的输出 namespace 重新解释旧 bytes；它不得声称是原 session 的相同结论，也不属于首个 CLI。

## 7. ESP32 wire 边界

### 7.1 唯一 dispatcher

```rust
fn decode_esp32_datagram(bytes: &[u8]) -> Result<Esp32Packet, DecodeError>;

enum Esp32Packet {
    Csi(Adr018Csi),
    ClockAnchor(Adr110Sync),
    Unsupported { magic: u32 },
}
```

同一 UDP 端口的 sibling magic 必须先分类。ADR-018 raw CSI magic 为 `0xC5110001`；`0xC5110002..=0xC5110007` 首版记录为已识别但不支持；ADR-110 clock anchor magic 为 `0xC511A110`。

decoder 必须：

- 检查 magic、最小 header、声明长度、endianness 和尾随 bytes；
- 检查 antenna/path 和 declared CSI sample count 大于零；
- 使用 checked multiplication 验证 payload 大小，不允许整数溢出；
- 限制 `max_datagram_bytes` 和配置允许的维度上限；
- 要求 `consumed == received`，不静默接受尾随数据；
- 保留原始 I/Q、sequence、RSSI、PPDU、flags 和协议给出的 radio metadata；
- 不调用 `Utc::now()`、monotonic clock 或随机数；时间全部来自 `CapturedPacket`；
- 对任意截断前缀返回 `DecodeError`，不 panic。

当前 firmware 的 ADR-018 头按下面的 20 bytes 解码；以实际 serializer 为准，而不是沿用旧文档的错误单位：

| bytes | wire value | 领域语义 |
| --- | --- | --- |
| 0..3 | `u32 LE` magic | `0xC5110001` |
| 4 | `u8` node | 仅用于 route |
| 5 | `u8` antenna/path count | 只映射 `RawPathOrdinal`，不证明 Tx/Rx |
| 6..7 | `u16 LE` firmware 所称 `n_subcarriers` | 实际仅为每 path 的 complex-pair count；不能保证一项对应一个物理 tone |
| 8..11 | `u32 LE` frequency | firmware 实写 MHz；零为 Unknown，转换 Hz 用 checked multiplication |
| 12..15 | `u32 LE` sequence | node 级全局序列，不是 profile 序列 |
| 16 | `i8` RSSI | dBm，按 firmware 契约 |
| 17 | `i8` noise floor | dBm，按 firmware 契约 |
| 18 | raw extension byte | 只有 route 声明 `he_tagging=true` 才解释 PPDU；否则 Unknown |
| 19 | raw extension byte | 同上；保留全部 bits，未知 bits 不丢失 |
| 20.. | ESP-IDF CSI complex pairs | 当前官方顺序为 `[imaginary, real]`；decoder 映射 `q=first, i=second`，长度严格匹配 path × declared sample count × 2 |

route 的 `Adr018Capabilities` 至少显式声明 firmware dialect、`he_tagging`、CSI acquire/LTF 配置和 frame-validity capability。bytes 18..19 为零不能证明 tagging 存在：它也可能是旧 firmware reserved-zero。未声明 tagging 时 PPDU/bandwidth 均为 Unknown；任何情况下都禁止用 sample count 推断 PPDU、带宽、LTF block 或 path 语义。

firmware 只是复制 ESP-IDF `info->buf`，没有序列化 `first_word_invalid`。旧 ADR-018 dialect 因此保守把 buffer 最前两个 complex pairs 标为 invalid（raw bytes 仍保留）；缺少所需 frame-validity flag 的 C6/HE dialect首个切片为 `InferenceIneligible::MissingFrameValidity`，只产生 reject health，不进入 baseline/world。固件补充显式 validity 后才放开。不能复用 RuView parser 的 `[I,Q]` 命名或把所有 pair 默认 valid。

当前 firmware 实际发送单 path。若 header 的 path count 不为 1，而 route 没有声明并通过 fixture 验证 multi-path sample order，则为 `InferenceIneligible::UnknownPathLayout`；不能仅根据 count 假定 path-major 排列。

### 7.2 ADR-018 能知道和不能知道的事

现有帧没有可靠 hardware ID、boot ID、发送方 MAC 和 per-frame capture ticks。因此首个切片：

- 设备和 link 来自 Registry route；
- boot generation 是 `HostInferred`，不能表述为硬件确认；
- event time 默认为主机 receive monotonic time；
- ADR-110 可以记录和诊断，但不能通过 sequence × 假定 FPS 宣称相干同步；
- firmware 增加 stable ID、boot ID、TX ID 和 capture ticks 后，才升级时间/身份质量。

ADR-018 的所有 path 在首个 decoder 中一律映射 `RawPathOrdinal`。即使 firmware 当前常见 count 为 1，也不能提升成 `TxRx`；只有 Intel 等协议真正提供 TX/RX 坐标时才使用 `CsiPath::TxRx`。

## 8. 类型化动态 CSI 契约

### 8.1 不是任意 rank tensor

Wi-Fi CSI 使用固定语义、动态长度：measurement path × CSI sample coordinate。只有协议真实提供物理 tone 坐标时，sample coordinate 才叫 tone。不会创建可塞入 Radar/UWB 的 `NativePayload` 空枚举，也不会创建任意 `FieldAxis[]`。

```rust
enum CsiPath {
    TxRx { tx_stream: u16, rx_chain: u16 },
    RawPathOrdinal(u16),
}

enum CsiSampleAxis {
    OpaqueSampleOrdinal { count: u16 },
    IeeeToneIndex(Box<[i16]>),
    FrequencyHz(Box<[u64]>),
}

struct CsiLayout {
    paths: Box<[CsiPath]>,
    samples: CsiSampleAxis,
    order: SampleOrder,              // 首版只允许 PathThenSample
}

struct IqSample {
    i: i32,                           // real；由 dialect 显式映射
    q: i32,                           // imaginary；由 dialect 显式映射
    valid: bool,                      // 只来自协议 flag 或保守 invalidation
}

struct CsiCapture {
    layout: CsiLayout,
    samples: Box<[IqSample]>,
    encoding: SampleEncoding,        // signed bits、scale、complex convention
    phase_state: PhaseState,
}
```

`CsiCapture::try_new` 必须验证：path/sample axis 非空；已知物理坐标无非法重复；complex sample 数严格等于 `paths × axis length`；乘法不溢出；坐标和 sample order 一致。

ADR-018 没有发送真实 IEEE tone index，也可能把多个 LTF block 拼在同一 buffer，因此只能使用 `OpaqueSampleOrdinal`。不能按长度伪造 `-N/2..N/2`，不能仅按 count 猜带宽或 MHz，UI 只能显示 “opaque CSI sample ordinal”，不能称为 subcarrier/tone。Intel 等协议提供真实 index 时才使用 `IeeeToneIndex`。

解码并完成 Registry 绑定后的领域记录为：

```rust
struct CsiObservation {
    input: InputReceipt,             // session + record_seq + decoder version
    sensor: SensorId,
    hardware: HardwareKind,
    link: RadioLinkId,
    device_sequence: u32,
    timing: FrameTiming,
    radio: RadioMetadata,
    profile: CaptureProfileId,
    csi: CsiCapture,
}
```

`CsiObservation` 不保存未知硬件的万能 metadata map；ADR-018 未提供的字段使用类型化 `Unknown/Option`，不能推测。

### 8.2 CaptureProfile 是兼容边界

```text
CaptureProfile descriptor
├── hardware kind + firmware/decoder version
├── wire-layout/acquisition capability ID
│   └── complex order, LTF selection/merge, validity dialect
├── channel/centre frequency/bandwidth: known or unknown
├── PPDU/PHY metadata: known or unknown
├── CsiLayout: path semantics + CsiSampleAxis + sample order
├── SampleEncoding and scale convention
├── phase capability/state
└── time capability/clock domain
```

descriptor 的字段只使用整数、枚举和显式 `Known/Unknown`；sample scale 编码为经过约分的整数 numerator/denominator，不使用 float 作为 identity。`CaptureProfileId([u8; 32])` 是 canonical-CBOR descriptor 的 SHA-256；遇到同 ID 但 descriptor 不同必须作为致命冲突。所有 `BTreeMap`、stream、baseline 和 API key 使用 ID，descriptor 由 Registry/profile catalog 查询。

静态 `Registry` 只保存部署配置；运行期发现的 descriptor 由 ingest task 独占的具体 `ProfileCatalog` 管理：

```rust
impl ProfileCatalog {
    fn intern(
        &mut self,
        descriptor: CaptureProfile,
    ) -> Result<CaptureProfileId, ProfileError>;

    fn snapshot(&self) -> ProfileCatalogSnapshot;
}
```

`intern` 先验证 descriptor，再 canonical encode/hash，并检查同 ID descriptor 完全相等。live 与 replay 按相同 record 顺序调用它；read store 接收 immutable catalog snapshot，供 API 将 opaque ID 展开为原生坐标/metadata。它不是 adapter registry，也没有 trait。

`StreamKey = (SensorId, RadioLinkId, CaptureProfileId)`；`StreamId = (StreamKey, HostEpoch)`。profile 任一兼容字段改变就切新流、新窗口和新 baseline；probable restart 切 `HostEpoch`；旧 profile 不丢弃，也不升级、padding 或合并成“最密网格”。API 使用 session 内稳定的 opaque `StreamId`，而不是让客户端传完整 profile 结构。

注意 sequence domain 比 stream/profile 更早：当前 firmware 的 `s_sequence` 是 node 全局计数。`SequenceSourceKey = (resolved route/SensorId, HostEpoch)`，Timeline 必须先在该 key 上分类 sequence，再把 observation 分入 link/profile stream。HT、HE 或 channel profile 交错不能制造假 gap；无法看到的 sequence 只记为 source-level gap，不能归因给某个 profile。

baseline 兼容 key 为：

```text
(DeploymentId, SpaceId, RadioLinkId,
 CaptureProfileId, ConditioningVersion)
```

下文 `LinkProfileKey` 是具体复合 key `(RadioLinkId, CaptureProfileId)`，不是新 trait 或带隐式匹配规则的 registry。

运行时绝不使用 dataset ID 选择 adapter。

## 9. 时间、sequence 与窗口

### 9.1 时间类型

```text
ReceiveTime
├── session_monotonic_ns        排序和首版窗口权威
└── utc_ns                      展示，不参与推理顺序

DeviceTime                      optional raw ticks + clock domain

EventTime
├── session_time_ns
├── source: ReceiveOnly | ClockCorrected
├── mapping_version
└── uncertainty_ns
```

```rust
struct FrameTiming {
    received: SessionTime,
    device: Option<DeviceTimestamp>,
    event: SessionTime,
    source: EventTimeSource,
    mapping_version: Option<ClockMappingVersion>,
    uncertainty_ns: u64,
}
```

只有可验证的 capture ticks 和 clock mapping 才能产生 `ClockCorrected`。coherence capability 单独建模；`ClockCorrected` 不自动等于可做相干相位融合。

### 9.2 sequence 和 epoch

每个 `SequenceSourceKey` 独立跟踪 `u32` sequence，使用 serial-number wrapping 比较，输出：

```text
First
InOrder
Gap { missing }
Duplicate
Reordered { distance }
Wrapped
ProbableRestart { reason, host_epoch }
```

近距离回退属于 reorder；从高值跨到低值且符合 wrapping 半区间属于 wrap；长时间 inactive 后大幅回退到低值可判为 `ProbableRestart`。所有启发式阈值在配置中带单位，并标记 `HostInferred`。随后才按 profile 分流；sequence health 属于 source，profile window 只携带与自身相关的 frame/missing-time 事实。

### 9.3 watermark 和窗口

```text
effective event time = corrected capture time if valid,
                       otherwise receive monotonic time

per-stream watermark = max_seen_event_time - allowed_lateness
global watermark     = min(watermark of active streams)
```

- 超过 `inactive_after` 的 stream 移出 active set，并在窗口中形成 missing span，不能永久卡住全局 watermark。
- active set 为空时，watermark 定义为最近已记录 `TimelineAdvance.at - allowed_lateness`，不会停在旧 stream。
- 首个切片使用对齐 session epoch 的固定非重叠窗口；有候选算法证明需要 overlap 后再加。
- `AlignedWindow` 保存每个 stream 的 frames、实际 timestamps、missing/gap、quality 和 profile，不补零。
- rate、jitter 和时间特征必须使用实际 `delta_t`，不能假设固定 FPS。
- late frame 仍在 session 中，但不修改已发布 snapshot；首个切片没有 state revision/supersedes。
- live 的 boundary schedule 由 session epoch 和固定 step 推导。每个到期 boundary 先 append 一个 `TimelineAdvance`；若 packet/command 与 boundary 同时，advance 先取得较小 `record_seq`，窗口采用半开区间 `[start, end)`，该 packet 属于下一窗口。replay 严格按 records 调用同一个 `Engine::advance_to(record.at)`；核心不读取墙钟。

`WindowContractId` 是 width、step、alignment、lateness/missing 语义和相关时间规则的 canonical digest；它不包含 session 起点或 WindowId。相同窗口语义可跨 session 兼容，任一语义变化则 candidate 明确不兼容。

## 10. 显式 conditioning

`CsiObservation` 不直接进入 baseline。conditioning 是可版本化的普通模块函数，输出动态 coordinate map 和 receipt，不输出固定 tensor。

```text
ConditionedWindow
├── window ID + interval
└── streams: BTreeMap<StreamId, ConditionedStream>
    ├── profile ID
    ├── coordinates[]: CsiPath × CsiSampleCoordinate
    ├── per-coordinate observed log amplitude
    ├── per-coordinate temporal absolute slope using actual delta_t
    ├── frame/coordinate validity
    ├── packet gap, rate, jitter and time quality
    └── ConditioningReceipt
```

首个 recipe：

```text
a = hypot(i, q) * declared_sample_scale
x = ln(1 + a)
```

其中 `declared_sample_scale` 必须为有限正数。窗口内对每个原生 coordinate 独立聚合；temporal slope 使用相邻有效 frame 的 receive-monotonic `delta_t`，零或倒退时间样本被排除。没有跨设备插值、frequency padding、per-segment `[0,1]` 缩放或 dataset-specific adapter。原始 phase 可查询和显示，但首个切片不让 phase 参与统计估计。

```rust
struct ConditioningReceipt {
    version: ConditioningVersion,
    first_record_seq: u64,
    last_record_seq: u64,
    stream: StreamId,
    window: WindowId,
    included_coordinates: u32,
    excluded: BTreeMap<ExclusionReason, u32>,
}
```

一个 `AlignedWindow` 一次转成一个 `ConditionedWindow`，保留所有 stream；每个 `ConditionedStream` 拥有自己的动态坐标和 receipt。`BaselineEstimator::step` 消费整窗，先更新各 link/profile belief，再只生成一个全局 `WorldSnapshot`，不会为每个 stream 产生互相覆盖的世界状态。

显式排除原因至少包含 invalid sample、missing、low coverage、unsupported phase、late 和 profile mismatch。首个切片不引入通用解释图、SHAP 或 attribution framework。

## 11. 最小时序 World Model

### 11.1 为什么它仍是 world model

首个统计估计器必须实现可编码的时序闭环，而不是给当前 window 做无状态分类：

```text
Prediction = predict(previous LinkEstimatorState, interval)
Assessment = score(Prediction, ConditionedWindow)
Decision   = gate(Assessment, quality, baseline lifecycle)
NextState  = optionally_update(previous state, observation, Decision)
Snapshot   = publish prediction + assessment + decision + evidence
```

masked reconstruction、共享 latent、Transformer 和跨设备 representation 是未来神经模型候选的晋升条件，不是当前统计估计器声称已经满足的目标。

### 11.2 动态坐标 baseline

baseline state key 为：

```text
(RadioLinkId, CaptureProfileId, CsiPath, native CsiSampleCoordinate)
```

Learning 阶段对每个 coordinate 独立维护 Welford `{count, mean, M2, accepted_exposure_ns}`：首个 accepted sample 设置 `count=1, mean=x, M2=0`，后续使用标准 Welford update。每个 accepted window 只把该 coordinate 在窗口内实际有有效 frame 覆盖的时间 span 累加到 exposure；两个 accepted window 之间的 missing/rejected gap 绝不计入。持久化 snapshot 只保存累计 exposure，不保存可跨 session 比较的 `SessionTime`。coordinate 同时达到配置的 `minimum_samples_per_coordinate >= 2` 和 `minimum_exposure_per_coordinate` 才是 ready；commit variance 为 `max(M2/(count-1), variance_floor)`。整体 ready-coordinate coverage 达到 `minimum_ready_coordinate_coverage` 后 baseline 才 mature。`Commit` 只固化 ready coordinates，未 ready 坐标以 `BaselineCoordinateUnready` 排除，不能靠 `variance_floor` 假装成熟。

Active 从 committed mean/variance 开始。对每个有效且 ready 的 coordinate：

```text
x_t       = window mean log amplitude
predicted = previous EW mean μ
r_t       = (x_t - μ) / sqrt(max(variance, variance_floor))
alpha     = 1 - exp(-accepted_exposure_t / ew_time_constant)

if gate accepts:
    delta     = x_t - μ
    μ'        = μ + alpha * delta
    variance' = (1 - alpha) * (variance + alpha * delta²)
```

`accepted_exposure_t` 只取本次 accepted window 中该 coordinate 的实际有效覆盖 span，并上限为 window width；它不跨 rejected/missing window 累积。新 session/rotation/host restart 后 `adaptation_armed=false`，首个 accepted window 只完成评分并把它设为 true，不执行 EW adaptation；后续 accepted window 才按自身 exposure 计算 alpha。所有坐标按稳定顺序归约。

`deviation_score` 是本 link 有效坐标 `|r_t|` 的配置分位数，是无量纲诊断 score，不是概率。分位数固定使用 nearest-rank：过滤 non-finite 后稳定升序排列，`rank = ceil(q × n)`（1-based）；`n=0` 返回 Unknown，禁止不同数学库自行插值。

首个切片的 `rf_dynamics` 只是窗口内 temporal absolute slope 的同一 nearest-rank 分位数，单位为 log-amplitude/second；它没有单独 baseline、不参与 Stable/Changing 判定，也不能称为人体 motion。实际证据证明需要归一化 dynamics 后，再为它增加独立统计状态。

window eligibility 是显式 conjunction，不产生一个含糊的综合 confidence：

```text
frame_count >= minimum_frames
AND ready_coordinate_coverage >= minimum_coordinate_coverage
AND packet_gap_ratio <= maximum_gap_ratio
AND receive_jitter <= maximum_receive_jitter
AND all used values/timestamps finite and ordered
AND event_time_source >= ReceiveOnly
AND source/link/profile resolved and compatible
```

每个谓词及实测值进入 `LinkQuality`。首个 ADR-018 非相干估计器接受 ReceiveOnly；coherent algorithm 另行要求更高 capability。

`variance_floor`、EW time constant、分位数、coordinate maturity、质量阈值和 link 状态阈值均按 `(link, profile, baseline revision)` 固化并记录。不同 link/profile 的原始 score 不假定可比较。默认值只能来自首批 calibration 数据和可复现实验，不能复制论文或 RuView 的常数。

`BaselineContractId` 是对 residual 定义、预测/标准化公式、数值精度和 incumbent eligibility 语义的 canonical 配置取 SHA-256；它写入 BaselineSnapshot、evidence 和 CandidateInput。它不包含学习得到的 mean/variance、`BaselineRevision` 或 state sequence，因此 rotation/持久化不会改变 contract；任何会改变 residual 含义或训练门控的配置/算法修改必须产生新 ID。

### 11.3 baseline 生命周期和污染门控

```text
Missing
  └─ BeginLearning command
       ▼
Learning { accepted_windows, duration, mature }
  └─ Commit command, only when mature
       ▼
Active ── Freeze ──> Frozen
  │                    │
  ├─ incompatibility/age ──> Stale
  └─ BeginLearning new revision / ActivateSnapshot
```

- `Learning` 只接收达到质量门槛的 window，但所有世界输出仍为 `Unknown::BaselineLearning`。
- 系统不能判断学习现场是不是“正常”；只有显式 `Commit` 才把 mature learning revision 变成 Active。
- Active 中严格按 `predict -> score -> decide -> optionally update -> snapshot` 执行。
- low quality、missing、time uncertainty、non-finite、profile mismatch、stale、frozen 或高 deviation 都拒绝更新。
- ADR-018 的 `ReceiveOnly` 对首个切片的单 link estimator 和非相干 belief fusion 是允许的；gap/jitter/coverage 进入质量门槛。它只禁止要求 capture-time 或 coherence 的算法，不能被笼统实现为“所有 ESP32 时间不合格”。
- `ProbableRestart` 关闭旧 HostEpoch 并将相应 baseline 标为 `Stale::ProbableRestart`；只有记录过的 Resume、BeginLearning 或 ActivateSnapshot 才允许再次适应。
- Active 只在 deviation 低于 `adaptation_gate` 时缓慢适应；显著变化不能被立即学成正常。
- `Stale` 不静默重建；需要兼容 baseline、记录过的 Resume、BeginLearning 或 ActivateSnapshot。
- `stale_after` 只使用当前 session 起点或最近 eligible evidence 的 monotonic age；baseline snapshot 不保存 UTC 用于自动 stale。新 session 重新开始该 timer。

每个 window 产生：

```text
BaselineDecision
├── BootstrapAccepted
├── AdaptationAccepted
└── Rejected(reason)
    ├── LowQuality | MissingData | TimeUncertain
    ├── ProfileMismatch | Stale | Frozen
    └── DeviationAboveGate
```

所有改变 lifecycle/revision 的 command 都进入 session 总序。

`BaselineCommand` 首个切片只有 `BeginLearning`、`Commit`、`Freeze`、`Resume` 和 `ActivateSnapshot { snapshot }`；重新学习复用 BeginLearning，不创建同义 Rebaseline API。`ActivateSnapshot` 自包含目标 snapshot，因此 session 可独立 replay。

`BaselineRevision` 表示不可变 persisted snapshot revision，只在 Commit、显式激活旧 snapshot、rotation 或 shutdown 时产生；`BaselineStateSequence` 在每次 accepted Active update 后单调增加。receipt 同时携带二者，避免同一 revision 内持续变化的 EW state 无法定位。Missing/Learning 时 revision/sequence 均可为空，不能伪造 0。

## 12. WorldSnapshot 与多设备融合

### 12.1 语义类型

```rust
enum Knowledge<T> {
    Known(T),
    Unknown { reason: UnknownReason },
}

struct LinkBelief {
    status: Knowledge<StableOrChanging>,
    diagnostics: Option<LinkDiagnostics>,
    quality: LinkQuality,
    baseline: BaselineStatus,
    evidence: EvidenceReceipt,
}

struct LinkDiagnostics {
    deviation_score: f64,
    rf_dynamics_log_amplitude_per_second: f64,
    prediction_error_summary: ResidualSummary,
}

struct SpaceBelief {
    status: Knowledge<StableOrChanging>,
    contributions: Vec<LinkContribution>,
}

struct WorldSnapshot {
    id: SnapshotId,
    previous_id: Option<SnapshotId>,
    deployment: DeploymentId,
    window: WindowId,
    valid_interval: TimeInterval,
    sensors: BTreeMap<SensorId, SensorHealth>,
    links: BTreeMap<LinkProfileKey, LinkBelief>,
    spaces: BTreeMap<SpaceId, SpaceBelief>,
    receipt: DerivationReceipt,
}

struct DerivationReceipt {
    source_session: SessionId,
    first_record_seq: u64,
    last_record_seq: u64,
    durable_through_record_seq: u64,
    config_digest: [u8; 32],
    build_fingerprint: [u8; 32],
    decoder_version: DecoderVersion,
    conditioning_version: ConditioningVersion,
    algorithm_version: AlgorithmVersion,
}
```

stable/change 是环境判断，RF dynamics 是带单位的信号动态诊断，unknown 是知识状态；三者不能塞进同一个概率和为一的枚举。status 在阈值中间可为 `Unknown::AmbiguousEvidence`，同时仍保留 diagnostics；只有完全无可评分坐标或 baseline 时 diagnostics 才为 `None`。首个切片不提供一个未经校准的 `uncertainty/confidence` 数；可核查的 coverage、time quality、baseline maturity 和 exclusion 保存在 `LinkQuality` 与 contributions 中。

### 12.2 首个切片的融合规则

首个切片不做 raw CSI、latent 或 phase coherent fusion，只融合 link belief：

1. 每个 `(link, profile)` 独立 predict/update。
2. 排除无 Active baseline、stale、时间/质量不足的 profile belief，并记录 exclusion。
3. 每个 profile 使用自己 `(link, profile, baseline revision)` 的 `stable_threshold/changing_threshold` 先得到 status；原始 score 不跨 profile/link 比较。
4. 在同一个 `RadioLinkId` 内先保守归约 profiles：任一 Changing 为 link Changing；全部 eligible profile Stable 为 link Stable；其余为 link Unknown。
5. space coverage 只数 distinct eligible `RadioLinkId`，同一物理 link 的 HT/HE profile 不能冒充两条覆盖链路。数量不足时为 `Unknown::InsufficientCoverage`。
6. 任一 eligible physical link 为 `Changing` 时，space 为 `Changing`。
7. 所有 eligible physical link 均为 `Stable` 时，space 为 `Stable`；其他组合为 `Unknown::AmbiguousEvidence`。始终保留每个 profile/link 的 status、原始 score 和 exclusion。

每条 link 的 `stable_threshold < changing_threshold`，避免边界抖动。该规则只聚合离散状态，不声称跨硬件 score 已校准；后续只有带 ground truth 的跨部署评估才能引入 normalized score fusion。

### 12.3 ID 与证据

首个切片只支持 faithful replay，因此 `SnapshotId = (SessionId, WindowId)`，不使用随机 UUID。UI 需要的 transition 由相邻 snapshot 现算；没有 Event/EventId/告警投递子系统。出现第一个真实外部告警消费者时，再以稳定 snapshot 对为输入设计幂等事件合同。

```rust
struct EvidenceReceipt {
    session_id: SessionId,
    first_record_seq: u64,
    last_record_seq: u64,
    link: RadioLinkId,
    profile: CaptureProfileId,
    conditioning_version: ConditioningVersion,
    baseline_contract: BaselineContractId,
    baseline_revision: Option<BaselineRevision>,
    scored_against_baseline_state_sequence: Option<u64>,
    resulting_baseline_state_sequence: Option<u64>,
    residual_summary: ResidualSummary,
    included_coordinates: u32,
    excluded: BTreeMap<ExclusionReason, u32>,
}
```

snapshot 内保存紧凑 receipt 和计数；精确坐标证据由 snapshot-pinned 查询从 bounded read store 返回 `CsiPath × CsiSampleAxis`、observed、predicted、signed residual、exact included mask、excluded reason 和 baseline revision，超出保留范围则由 faithful replay 重算。这样既能回答具体哪些坐标参与，又不把每个 snapshot 膨胀成完整信号副本。

`BaselineEstimator::step` 在同一次评分中使用 pre-update state 产生 transient `CoordinateEvidence`。Engine 再把 timeline continuity 与 incumbent decision 合成 `CandidateInput`；app 只能按序转交，不能重算 eligibility。`EngineOutput` 携带 candidate inputs 和 snapshot，app 可把 evidence 放进 bounded snapshot-pinned read store，closed-session learner 可在 faithful replay 时直接消费；它不另写一份 derived session log。

```rust
struct CoordinateEvidence {
    path: CsiPath,
    coordinate: CsiSampleCoordinate,
    observed: Option<f64>,
    predicted: Option<f64>,
    signed_residual_log_amplitude: Option<f64>,
    standardized_residual: Option<f64>,
    exclusion: Option<ExclusionReason>,
}

struct LinkStepEvidence {
    stream: StreamId,
    link_profile: LinkProfileKey,
    baseline_contract: BaselineContractId,
    baseline_revision: Option<BaselineRevision>,
    scored_against_baseline_state_sequence: Option<u64>,
    resulting_baseline_state_sequence: Option<u64>,
    baseline_decision: BaselineDecision,
    link_status: Knowledge<StableOrChanging>,
    quality: LinkQuality,
    coordinates: Vec<CoordinateEvidence>,
}

struct EstimatorStep {
    snapshot: WorldSnapshot,
    links: Vec<LinkStepEvidence>,
}

struct CandidateInputId {
    session: SessionId,
    stream: StreamId,
    window: WindowId,
}

struct CandidateInput {
    id: CandidateInputId,
    deployment: DeploymentId,
    conditioning_version: ConditioningVersion,
    link_profile: LinkProfileKey,
    predecessor: Option<CandidateInputId>,
    window_contract: WindowContractId,
    baseline_contract: BaselineContractId,
    baseline_revision: Option<BaselineRevision>,
    scored_against_baseline_state_sequence: Option<u64>,
    eligibility: CandidateEligibility,
    coordinates: Vec<CoordinateEvidence>,
}

enum CandidateEligibility {
    Eligible,
    Rejected { reasons: Vec<CandidateRejection> },
}

struct EngineOutput {
    snapshot: WorldSnapshot,
    candidate_inputs: Vec<CandidateInput>,
}
```

`standardized_residual` 就是第 11.2 节用本窗 **更新前** baseline state 算出的 `r_t`；candidate 不得从 signed residual、mean 或 variance 重算。`CandidateEligibility::Eligible` 只表示当前窗同时满足 `AdaptationAccepted`、link status 为 `Known(Stable)`、source gap 为 0，且至少一个未排除的 finite standardized residual，并保证 `baseline_revision.is_some()`。每个 `coordinates` 按 `(CsiPath, CsiSampleCoordinate)` 严格递增且无重复，`EngineOutput.candidate_inputs` 按 `CandidateInputId` 稳定排序。`predecessor=Some(id)` 只在 timeline 证明前窗与当前窗属于同 session/stream/revision/WindowContractId 且连续时产生；首窗或任何边界为 `None` 并只允许 seed cursor。Unknown、Changing、gap、rejected window 均给出 typed reason 并清 cursor。

首个切片只保存可核查事实和统计 contribution，不引入 SHAP。UI 的 residual 是直接证据；未来 latent heatmap 只能标为模型 attribution，不能标为 RF 世界事实。

## 13. 查询与可视化契约

### 13.1 API

```text
GET  /api/topology
GET  /api/signals?sensor=&link=&profile=&from=&to=&metric=&max_time_buckets=
GET  /api/timeline?sensor=&link=&from=&to=
GET  /api/world?from=&to=
GET  /api/world/latest
GET  /api/world/{snapshot_id}/evidence?link=&profile=
GET  /api/baselines?link=&profile=
POST /api/baselines/commands
WS   /api/live
```

非法 query 返回 4xx；不存在或证据不足返回 typed empty/unknown，不返回伪造数据。首个 HTTP server 只查询配置容量/时长内的 recent read store；超出范围返回 typed `RangeUnavailable { available_from, available_to }`。完整历史只由离线 replay CLI 处理，server 不临时启动 Engine。

### 13.2 SignalView

```rust
struct SignalQuery {
    sensor: SensorId,
    link: RadioLinkId,
    profile: Option<CaptureProfileId>,
    interval: TimeInterval,
    path: Option<CsiPath>,
    metric: I | Q | Amplitude | Phase,
    max_time_buckets: u16,
}

struct SignalTile {
    stream: StreamId,
    profile: CaptureProfileId,
    time_axis: Vec<SessionTime>,
    path_axis: Vec<CsiPath>,
    sample_axis: CsiSampleAxisDto,
    order: TimePathTone,
    cells: Vec<Option<SignalBucket>>,
    aggregation: Raw | MinMaxMeanRmsCount,
    missing_spans: Vec<TimeInterval>,
    receipt: ViewReceipt,
}
```

查询结果是 `Vec<SignalTile>`，每个 StreamId/profile 一个 tile；未指定 profile 时可返回多个 tile，但不把它们凑成一个矩阵。`None`/missing span 表示缺失，零是合法测量值，二者不能混用。

I、Q 和 amplitude 缩小时以 viewport 的 `max_time_buckets` 现算 min/max/mean/RMS/count；放大后返回原生点。wrapped phase 在首个切片只允许 raw，不做线性 min/mean/RMS；超过 point budget 返回 422 并要求缩小范围。明确 circular aggregation 及其 receipt 后才能下采样 phase。

首个切片不建多分辨率缓存，测到查询成本后再加。不同设备默认分面显示，不能只读 `nodes[0]`，也不能取模复制短数组。Deviation 只从 snapshot-pinned evidence endpoint 查询，避免 baseline 更新后同一普通 signal query 得到另一种解释。

### 13.3 首个页面

一个普通二维诊断页包含：

- topology 和 link/profile selector；
- 按设备/profile 分面的 time × native CSI-coordinate 图；
- sequence gap、restart、rate、jitter、profile、baseline command 时间线；
- 每条 link 的 predicted vs observed、deviation、RF dynamics、quality；
- space 的 Stable/Changing/UNKNOWN、link contributions 和 exclusion reason；
- baseline lifecycle、maturity、revision 和最近 decision。

所有图明确轴语义和单位。`OpaqueSampleOrdinal` 不显示为 subcarrier、tone 或 MHz；没有几何就不画空间热图；没有人类标签就不画人体。断开 live 时显示 `DISCONNECTED`，首个切片没有 synthetic 数据路径。

### 13.4 Live envelope

```text
LiveEnvelope
├── http_schema_version
├── delivery_sequence
└── payload
    ├── SensorHealthChanged
    ├── WorldSnapshotAdded { snapshot_id }
    └── BaselineChanged { link, profile, revision }
```

WebSocket 不持续发送整个历史或 giant world payload。慢客户端丢 delta 后按 ID 重新 GET；delivery mode/sequence 不进入 semantic snapshot。

## 14. 运行时所有权、背压与错误

### 14.1 任务与所有权

唯一 ingest task 顺序执行：

```text
recv/select packet or baseline command
  -> assign record_seq and session time
  -> SessionWriter::append().await
  -> decode/resolve
  -> Engine::push() / command() / advance_to()
  -> update bounded read store
  -> try_send small live notification
```

- `Engine`、`Timeline`、`BaselineEstimator` 没有共享锁。
- HTTP baseline command 进入有界 command queue；满时返回 503，不静默丢弃。
- read store 保存近期 observation、immutable snapshot 及其 snapshot-pinned coordinate evidence；超出 recent 范围的历史只由离线 replay CLI 查询。
- WebSocket 使用有界队列；慢客户端跳到最新状态或断开，不能反压感知。
- UDP 本身不可反压。顺序写盘过慢造成的 gap 由 sequence/ingest health 展示；先测量，确认瓶颈后才拆 writer task。
- socket receive buffer 为完整 UDP datagram 分配 `UDP_MAX_DATAGRAM_BYTES = 65_535`，收到完整长度后再按配置 `max_datagram_bytes` 记录并拒绝超限包；不能用业务上限大小的 buffer 静默截断 datagram。
- parse reject、unknown route、socket gap、writer latency、view drop 都有独立指标。

### 14.2 shutdown

shutdown 顺序固定：停止接受新 command 和 socket receive；处理已经接收的输入；append `Closed(record_seq, at)`；以该记录调用 `Engine::finish(at)` 关闭剩余 window；flush + `sync_data` session；把 baseline snapshot 写入 temp 并 sync；atomic rename current pointer 并 fsync 所在目录；最后关闭 HTTP/WS。baseline snapshot 必须记录 source session、last durable record seq 和内容 digest，任何 current pointer 都不能领先 durable session。

### 14.3 错误策略

| 情况 | 行为 |
| --- | --- |
| bad magic/length/count/overflow/trailing bytes | raw 已记录；增加 decode reject；继续 |
| 未登记 peer/node/link | raw 已记录；拒绝进入 timeline/estimator |
| route/ID/config 冲突 | 启动失败 |
| late/duplicate | 分类并排除；不重写历史状态 |
| session append/flush 失败 | 立即停止 capture |
| replay 中间 CRC/不支持版本 | 带 offset/version 失败 |
| crash tail | 恢复完整前缀并明确告警 |
| baseline 不兼容 | `Stale` 或启动失败；不静默重建 |
| 证据不足 | `Unknown(reason)`，不是应用错误 |
| HTTP 参数非法 | 4xx |
| 内部不可能不变量 | 可 panic，消息必须说明不变量和上下文 |

领域边界保留可分类的 `ConfigError`、`DecodeError`、`SessionError`、`TimelineError` 和 `EstimatorError`；应用层可以增加统一上下文，但不能抹平分类。

## 15. 核心同步 API

以下是实现边界，不要求现在把所有类型公开给外部 crate：

```rust
struct Esp32Decoder;

impl Esp32Decoder {
    fn decode_and_resolve(
        &self,
        packet: &CapturedPacket,
        registry: &Registry,
        profiles: &mut ProfileCatalog,
    ) -> Result<DecodedInput, IngestError>;
}

enum DecodedInput {
    Csi(CsiObservation),
    ClockAnchor(ClockAnchorObservation),
    Unsupported { magic: u32 },
}

fn condition(
    window: &AlignedWindow,
    recipe: &ConditioningRecipe,
) -> Result<ConditionedWindow, ConditioningError>;

struct Timeline;

impl Timeline {
    fn push(&mut self, observation: CsiObservation) -> TimelineOutput;
    fn advance_to(&mut self, now: SessionTime) -> Vec<AlignedWindow>;
}

struct BaselineEstimator;

impl BaselineEstimator {
    fn step(&mut self, window: &ConditionedWindow)
        -> Result<EstimatorStep, EstimatorError>;
    fn command(&mut self, command: &TargetedBaselineCommand)
        -> Result<(), EstimatorError>;
    fn snapshot(&self) -> BaselineSnapshot;
}

struct Engine {
    timeline: Timeline,
    conditioning: ConditioningRecipe,
    estimator: BaselineEstimator,
}

impl Engine {
    fn push(&mut self, observation: CsiObservation)
        -> Result<Vec<EngineOutput>, EngineError>;
    fn advance_to(&mut self, now: SessionTime)
        -> Result<Vec<EngineOutput>, EngineError>;
    fn command(&mut self, command: TargetedBaselineCommand)
        -> Result<Vec<EngineOutput>, EngineError>;
    fn finish(&mut self, at: SessionTime)
        -> Result<Vec<EngineOutput>, EngineError>;
}
```

证据不足是正常的 `Knowledge::Unknown`。只有数值非法、状态机不变量破坏或配置/版本不兼容进入 `Err`；`Engine` 不吞掉 `EstimatorError`。

`main.rs` 只解析 CLI 后调用 `app`。首个切片不承诺公共 SDK；尽可能使用 `pub(crate)`，外部真正出现消费者后再稳定 public API。

## 16. 确定性 replay 规则

- live 和 replay 共享同一个 decoder、Registry、Timeline、conditioning、`BaselineEstimator` 和 Engine 路径。
- 核心接收显式 session time；不调用墙钟或 sleep。
- `BTreeMap` 或显式排序定义 link/coordinate/space 归约顺序。
- 所有 baseline command 与 packet 共用 `record_seq` 总序。
- snapshot 的确定性内容不含 live/replay delivery mode、处理耗时或当前主机信息。
- 浮点验收范围为同一 executable、target 和配置；跨硬件 bitwise reproducibility 需要实际需求和数值方案后再承诺。
- replay 只产生 typed snapshots，不执行 HTTP/WS 等外部交付副作用。

## 17. ESP32、多设备与 Intel 5300 的兼容方式

兼容性的稳定边界是：身份、link、time quality、CaptureProfile、类型化 `CsiCapture`、conditioning receipt 和纯 Engine contract，不是 adapter trait。

首个切片必须用内存构造并验证一个 `TxRx 3 × 3`、30-tone 的 `CsiCapture` 可以通过 domain、timeline、conditioning、estimator 和 view，而无需修改这些模块。该测试证明领域类型和统计路径没有 ESP32 固定形状；它不表示 Intel wire/driver 已实现。

Intel 5300 到来时只新增：

1. 真实采集 transport 输入；
2. Intel decoder/resolver；
3. 对 sample encoding、tone index、TX/RX path、device timestamp 和 phase state 的诚实映射；
4. 新的协议 fixtures 和兼容性测试。

多个 ESP32、ESP32 + Intel 或多个 profile 的 CSI 不在 raw 层拼接。它们先独立产生 link belief，再按第 12 节在 space 层融合。

相干融合额外要求共同 clock/LO 或被验证的 coherence group、capture timestamp 和误差上界。未通过 gate 的设备只能做非相干 belief fusion。

运行时部署模型的兼容检查使用：

```text
(CaptureProfileId, ConditioningVersion, AlgorithmVersion)
    -> Supported | Unsupported(reason)
```

不能使用 dataset name、bin count 或硬件营销名称暗中选择预处理。

## 18. 评估与数据泄漏边界

任何统计阈值、神经模型 artifact 或未来 RF 预训练模型的评估 manifest 至少记录：

```text
deployment / room / day
device hardware + firmware + boot/session
link + channel + capture profile
person/trial/label provenance when present
calibration partition + session/window references
target-domain data used: none | unlabeled calibration | labeled few-shot
quiet/normal command provenance and operator
decoder/conditioning/algorithm/baseline versions
split assignment and seed
```

split 必须在 preprocessing、baseline fit、windowing、augmentation 和 sampling 之前，按实验声明的 deployment/room/day/device/boot/session/person/trial 分组。calibration window 不得与 test window 重叠。重叠 window 不得跨 split。随机切 frame 后再 window 的结果视为 leakage，不得用于泛化声明。

报告必须区分 `no target data`、`unlabeled target calibration` 和 `few-shot target labels`。使用过目标房间 quiet bootstrap 的结果不能称为 zero-shot。

首个切片没有监督学习，但 session/replay 验收仍按不同设备、profile、重启和房间分组，避免只验证单一稳定场景。

## 19. CPU 自监督、候选演化与性能合同

### 19.1 可行性裁决与三条执行路径

“GPU 预训练、CPU 部署学习”可行，但必须把三种计算分开：

| 路径 | 执行位置 | 可变状态 | 是否影响 live 世界状态 |
| --- | --- | --- | --- |
| 统计 baseline estimator | 部署 CPU、ingest 顺序热路径 | 受门控的 per-link baseline | 是；最小内核的权威生产路径 |
| 原生自监督候选 | 部署 CPU、closed-session replay/低优先级 shadow | 动态坐标 AR(1) residual predictor；输出不可变候选 | 否；通过语义准入前只产生 shadow 诊断 |
| 预训练表示候选 | 上游 GPU 训练主干；部署 CPU 只 forward/小头学习 | 冻结 encoder + diagonal latent head | 否；只向部署端交付并验证带摘要的 artifact |

因此这里的“自我演化”是可审计的候选闭环：用新 session 生成新 head，固定成 artifact，在未见过的 session 上评估，shadow 运行，再显式选择或回滚。它不是采集进程一边判断一边反向传播，也不是让自监督 loss 自动取得生产决策权。

只使用无标签目标域数据时，报告名称必须是 `self-supervised adaptation`，不能声称 presence、人体动作或其他语义准确率提高。预测 loss 下降只证明 latent 更可预测，未证明世界状态更正确。

### 19.2 最小 CPU 候选，不建立训练框架

第一个候选不需要神经网络。它预测现有 baseline 已产生的每个动态坐标标准化 residual：

```text
r_t(c)             = baseline standardized residual at coordinate c
predicted_r_t+1(c) = beta(c) * r_t(c)
error              = r_t+1(c) - predicted_r_t+1(c)

beta'(c) = clamp(
    beta(c) + learning_rate * r_t(c) * error
              / (normalization_epsilon + r_t(c)^2),
    -maximum_abs_beta,
    maximum_abs_beta,
)
```

这是 normalized LMS 的逐坐标 AR(1)，不是固定数组。上一 residual 的 pair cursor 与可跨 session 使用的 sealed 参数不是同一个 key：

```text
PairCursorKey =
  (SessionId, StreamId, BaselineRevision, WindowContractId,
   CsiPath, native CsiSampleCoordinate)

ArParameterKey =
  (DeploymentId, RadioLinkId, CaptureProfileId, ConditioningVersion,
   BaselineContractId, WindowContractId,
   CsiPath, native CsiSampleCoordinate)
```

`ForecastContractId` 是 target quantity/unit/scale、`BaselineContractId`、`WindowContractId`、horizon、coordinate/mask semantics 和 forecast loss/version 的 canonical digest。首个合同固定为“预测下一窗由 pre-update baseline 产生的 native-coordinate standardized residual”；以后 AR、RF 预训练模型与 RF 部署模型只有该 ID 相同时才能比较，蒸馏实验也必须遵守该合同；不增加通用 ForecastQuantity enum。

cursor 只保存上一 eligible residual/时间，任何 session/epoch/revision/window boundary 都清除。parameter 保存 `beta`、pair count 和误差统计；它明确包含 `CsiPath`，但不包含会在 rotation 后变化的 epoch/revision，因此同一部署/链路/residual 定义的 sealed artifact 能在后续 session 命中。训练使用过的具体 epoch/revision 只进入 provenance receipt。训练与预测都是 `O(本窗有效坐标数)`。`beta=0` 等价于预测 residual 回到 baseline mean。`learning_rate`、`normalization_epsilon`、`maximum_abs_beta`、`minimum_pairs_per_coordinate` 和 ready-coordinate coverage 都是有界 manifest 输入；值必须由 calibration/holdout 决定，不能复制论文。

seal 时只按稳定 key 顺序写入达到 minimum pairs 的坐标；未 ready 或运行时新出现的坐标 abstain，并回到 incumbent prediction。artifact 的 coordinate 数受兼容 CaptureProfile 的动态上限和 `max_artifact_bytes` 双重约束。

训练 pair 必须来自相邻、相同 session/stream/baseline revision/WindowContractId 的 eligible window；`StreamId` 已包含 HostEpoch，不能再存一份可能冲突的 epoch。gap、restart、profile change、baseline revision change、low quality、Changing 或被 incumbent gate 拒绝的 window 会清除上一 residual，不能成为 target。candidate 不能使用自己的输出决定训练 eligibility。

每个 CandidateInput 的顺序语义固定为：

```text
if cursor.input_id != current.predecessor or current is rejected:
    clear cursor

if current is eligible and cursor exists:
    prediction_t = sealed_or_scratch_beta_before * cursor.residual
    error_t      = current.standardized_residual - prediction_t
    training only: update scratch beta(cursor.residual, error_t)

if current is eligible:
    cursor = current input/residual
```

上述逻辑按每个 native coordinate 独立执行：当前坐标 excluded、missing 或 non-finite 时只清该坐标 cursor；有效 residual 只有在 `cursor.input_id == predecessor` 时才形成 pair，否则只 seed。首个 eligible window 只 seed cursor 并 abstain。`learn-ar1` 只更新 training scratch；seal 后的 artifact 在 holdout、shadow 和 replay 中绝不更新 `beta`。candidate 与 `beta=0` incumbent 必须消费同一次 replay 产生的同一 CandidateInput stream，不能各跑一次 baseline 后再比较。

这个 AR candidate 直接保留动态坐标，不需要 tensor、autograd、BLAS 或 ML backend。若 holdout 证明它不优于 `beta=0` incumbent，就删除该 candidate，不把复杂度升级当功能进度。

GPU 预训练模型是其后的独立候选路径：

```text
z_t             = frozen_encoder(artifact_pack(ConditionedStream_t))
predicted_z_t+1 = a ⊙ z_t + b
loss            = mean(huber(predicted_z_t+1 - stop_gradient(z_t+1)))
```

部署 CPU 对每个 link/profile stream 独立执行 frozen encoder forward，并训练长度为 `2 × latent_dimension` 的 `a/b`；encoder、input normalization 和 `artifact_pack` 均冻结。artifact 必须记录私有 input/output shape、dtype、坐标/mask 映射、所需算子、encoder digest、支持的 `(CaptureProfileId, ConditioningVersion)` 以及 CPU backend/version/thread 数。领域/session/API/UI 不知道 latent dimension，也不保存 canonical tensor。首个 encoder 不接收全局 `ConditionedWindow` 或固定 stream 数；真正的多-link encoder 等真实拓扑合同出现后再设计。

不兼容 profile 返回 `UnsupportedModelInput`，统计 baseline 正常工作。Intel 5300 或新 ESP32 profile 先获得兼容 artifact；没有证据前不强迫不同硬件共享 latent/head。只有 diagonal head 在 holdout 和 CPU 基准上同时证明不足时才试 low-rank head；全主干 CPU fine-tune、首个候选 Transformer 和 production test-time adaptation 明确拒绝。

### 19.3 Artifact、数据所有权与运行方式

CPU 演化切片在同一个 package 中只增加一个具体 `candidate.rs`；它最初只依赖 `domain`，包含动态 AR(1)、artifact 校验和 bounded training step。真实 frozen encoder 通过 spike 后才增加 `conditioning` 依赖和一个选定的 CPU backend。`app` 组合以下 CLI，不增加 `learner.rs`、训练服务、神经模型 registry、backend trait 或远程控制面：

```text
durable closed session
        │
        ▼
faithful replay -> incumbent residual/decision receipt
        │                       │
        │ eligible only         └-> time-forward holdout comparison
        ▼
bounded AR learner -> seal immutable candidate -> selected shadow

live EngineOutput -> bounded shadow queue -> candidate diagnostics
        └---------- production WorldSnapshot is unchanged ----------
```

这是一条从事实日志向 candidate 的单向旁路；candidate 不回调、不持锁、不阻塞 Engine。

```text
world learn-ar1 <closed sessions...>
world evaluate-candidate <candidate> <holdout sessions...>
world select-shadow <candidate> <evaluation-report>
world rollback-shadow <previous-candidate> <its-evaluation-report>
```

- `learn-ar1` 只读取正常关闭或 recovery-sealed 的 immutable session，并复用 replay 的 decoder、timeline、conditioning 和 pinned baseline decision；不能订阅 live mutable window。
- 这是 nearline continual learning：新鲜度下限受 session rotation 周期和 catch-up time 限制，不承诺每窗立即改权重。`learning_lag` 必须可见；不能为了降低它频繁 rotation，导致第 11.3 节的 `adaptation_armed=false` 反复跳过更新。
- 首实现与 `capture` 排他运行，不提供并发开关、pause IPC 或后台 worker。真有并发新鲜度需求后，先设计 session lease 和协作暂停，再通过联合负载测试；不能只靠 OS priority 偷跑。
- `learn-ar1/evaluate-candidate` 把 immutable candidate/report 写到调用者指定路径；重复训练写新文件，不覆盖旧文件。只有 `select-shadow/rollback-shadow` 验证二者后才把它们导入 content store，并原子更新 selected sidecar。GC 只保护 retained manifest 和当前 selected sidecar 引用的 digest；其他输入文件由调用者管理。不建 new/previous 指针或 registry。
- shadow artifact 在 session 开始前确定，durable 存入第 6.2 节的 content-addressed attachment 并由 manifest pin 住。缺失或摘要不符时拒绝启用；同一 live session 内不换 artifact。导出 session 时必须连同 pinned artifact 一起导出。
- `select-shadow/rollback-shadow` 首实现只在取得 runtime lock 后成功，验证 report 指向 candidate，并原子更新下一 session 的 `ShadowSelectionPin`；不为它增加进程间控制面。若正在 capture，明确拒绝并要求先完成 shutdown。
- 训练 checkpoint 不是 production artifact；optimizer state 不进入 capture。

最小 `CandidateManifest` 包含：

```text
optional parent candidate digest + candidate algorithm version
compatible deployment/link/profile/conditioning/baseline/window/forecast contract
dynamic coordinate parameters + numeric precision
training session/window references + eligibility rules
loss/update/pass/example limit/order/seed
```

artifact 内不保存自己的 digest，也不反向引用后生成的评估。seal 完成后对 bytes 计算 `candidate_digest`；独立 immutable `CandidateEvaluationReport` 单向记录该 digest、time-forward holdout refs/split、mean/tail/coverage/abstention 结果，并直接嵌入第 19.4 节的 reference hardware/workload/executable profile、性能分位数与失败计数。首实现没有第三种 PerformanceReport attachment。`select-shadow` 必须同时验证并记录 candidate/report 两个 digest。

frozen encoder 候选到来时才在其具体 manifest 附加 encoder digest、packing recipe、私有 latent shape、runtime backend 和显式线程设置，不为尚不存在的 artifact 预写通用 union。

随机性不是必需品；首实现使用稳定 session/window/link 顺序。若后续确需 shuffle，seed 和确切 permutation algorithm 才成为版本化输入。

### 19.4 性能事实、预算与准入报告

“能在 CPU 跑”必须由目标主机实测，不接受桌面机乘系数推算、Mock backend、合成 no-op 模型或只报平均值。每份报告同时固定：

```text
ReferenceHardware
├── CPU model / ISA / physical and logical cores
├── RAM / storage / OS / kernel
└── power and frequency policy when controllable

WorkloadProfile
├── device/link/profile count
├── active stream count and stream -> artifact digest mapping/instance count
├── per-stream packet rate and dynamic coordinate bounds
├── window width/step, session sync policy and query load
└── encoder/candidate digest and artifact size

ExecutableProfile
├── git/build/target/compiler/profile
├── backend/precision/intra-op/inter-op threads
└── runtime configuration digest
```

报告同时定义：

```text
R_peak = sum(routes[].peak_packets_per_second)
B_peak = sum(routes[].peak_packets_per_second
             * routes[].maximum_valid_datagram_bytes)
T_step = global world window step
L_no_shadow = 相同 1× capture/query workload 下 shadow disabled 时
              window_due -> WorldSnapshot available 的 P99
```

capture 配置始终必须填入 `max_rss_bytes`、允许的 CPU 线程数和 `snapshot_deadline`，其中 `snapshot_deadline <= 0.5 × T_step`。candidate disabled 时无需伪填训练预算；启用 shadow 或调用 learner 时才强制验证 `max_artifact_bytes`、`max_learning_lag` 和 candidate 线程/RSS 上限。未给出最低支持主机时，架构只能判定可行，不能宣称已达到部署性能。

首个参考硬件上的 go/no-go 合同是：

1. capture harness 固定真实 datagram corpus digest，分别运行两个 30 分钟 workload：packet-bound 按**每条 route** 的 `2 × peak_packets_per_second` 分布 paced 注入；byte-bound 使用每条 route 真实、decoder 可接受的 maximum-size fixture 达到 aggregate `2 × B_peak`。缺少这种 fixture 就不能通过 byte-bound gate，不能以理论 maximum 或合成 no-op payload 代替。两次均重新 durable append，新增 application/kernel drop、write failure 和未解释 sequence gap 为 0；报告逐 route achieved pps、aggregate bytes/s、corpus digest 和 decoder success count。
2. 在 `1×` live 负载、声明的 HTTP/WS 查询负载和 candidate shadow 同时存在时，`window_due -> WorldSnapshot available` 的 P99 不超过 `snapshot_deadline`。
3. faithful replay 分别跑 packet-bound 与 byte-bound corpus，持续处理能力达到各自声明 workload 的 `2×`；报告 achieved pps/bytes/s，并分别列出 read、decode、condition、baseline 和 candidate stage。
4. candidate 冷启动、每窗 inference P50/P95/P99、峰值 RSS、artifact bytes 和每窗分配量分别报告，不能用吞吐均值掩盖 deadline miss。
5. `learn-ar1` 限一个 CPU worker，固定 corpus 的处理速度不低于 eligible 数据产生速度，峰值 RSS/输出大小在配置预算内，且无 NaN/Inf。
6. shadow on/off A/B 使用相同 paced input；开启 shadow 后不能新增 drop，hot-path P99 不超过 `1.10 × L_no_shadow` 且仍满足绝对 deadline。比较的是去除 shadow/config/delivery receipt 后的 production semantic projection，不能错误要求两个完整 envelope digest 相同。
7. 不写第二份 decoded CSI 训练集；学习额外写入只有 bounded artifact/report。启动前 free bytes 至少覆盖实测 session P99 bytes/second × retention period × 2、所有 retained-session pins 和当前 selected sidecar；调用者路径中的未选择输出另由 CLI 在写入前检查 artifact/report 上限。managed store 的历史文件数量只能随明确 retention 上限增长。
8. `learning_lag = latest durable eligible event emitted by live Engine（包含 active session） - latest event covered by newest sealed candidate`；另报 selected shadow 覆盖到的 event age。没有 candidate 时为 typed unavailable，不得显示 0。超过 `max_learning_lag` 只报告 `CandidateBehind`，不能改变 baseline、自动选择 candidate artifact 或停止事实采集。

首个 CPU 演化切片只支持持有 runtime lock 的分时/离线 learner，不宣称 capture 与 learner 并发。session 最大时长、计划运行间隔和实测 catch-up time 必须让 `max_learning_lag` 可满足；真有并发需求后再以 session lease 和联合干扰基准升级。

`2×` 是首个准入的负载余量，不是领域常量；产品以后可以提高，不能在没有风险证据时降低。benchmark 保存原始分位数样本/直方图与失败计数，CI 只跑小型正确性检查；实机 soak 是发布门禁，不能伪装成每次提交都稳定的微基准。

AR(1) candidate 不需要 runtime backend。frozen encoder 到来后，若选择 ONNX Runtime 作为唯一 CPU backend，初始设置为明确的一条 intra-op 线程和一条 inter-op 线程，并关闭会持续占核的 spinning；只有实机证明不会挤占 capture 才调高。官方文档说明默认 CPU session 可能为每个物理核心创建线程，因此默认值不是安全配置。FP32 是首个基线；INT8 只有同时改善目标 CPU 的 latency/RSS 且通过数值/质量回归才采用，不能假设量化必然更快。CPU FP16 不作为方案。

### 19.5 调度、降级与生产安全

CPU 资源优先级固定为：

```text
durable raw ingest > statistical baseline/world > selected production inference
                   > shadow inference > read-view aggregation
```

协作式降级状态只有：

```text
Normal -> DisableShadow -> ReduceViews -> StatisticalOnly
```

- raw session append 和统计 baseline 没有可丢的内部队列；跟不上就按第 14 节停止 capture，而不是悄悄跳包。
- shadow 队列有界；满或 deadline miss 时只跳过 shadow，记录非语义 runtime health `ShadowSkipped(reason)`，不写入 WorldSnapshot、不能要求 faithful replay 复现墙钟 deadline，也不反压 ingest。跳过后 predecessor mismatch 必须清该 stream cursor。
- 离线 learner 只拥有 mutable scratch；失败/中断就丢弃 scratch 并按固定 corpus 顺序重跑，首实现不发明 checkpoint/cursor 协议。它不得持有 production head 或写历史 session。
- live 状态转换只看 receive-to-append lag、writer/sync latency、kernel UDP drop、sequence gap、watermark lag、RSS 和 read-store/query pressure；每个阈值属于 PerformanceProfile。
- `ReduceViews` 只降低 viewport point budget、拒绝超预算历史 query 或断开慢 WS；不改变 Engine input、WorldSnapshot 或 retained evidence。
- 不依赖 OS `nice` 或线程优先级提供正确性。发生越界时按上述状态顺序协作停工；不能先牺牲 raw 事实源或改变 baseline 算法。
- 将来若 candidate 获准进入生产推理，backend error/deadline 决策必须先成为有序 session 输入，再以 `ModelFallback(reason, candidate_digest)` 写入 receipt 并回到统计 baseline；不能只靠 replay 时的墙钟或静默伪装成 candidate 成功。

### 19.6 评估、选择与回滚边界

训练/holdout 必须先按第 18 节分 session，再进行 windowing 和 pair 构造。候选至少通过：

- candidate 与 incumbent 使用同一 pinned baseline snapshot、window、coordinate mask 和 eligibility receipt；
- 未参与训练的、更晚 session 上 mean 与 tail forecast error 相对 parent 改善，coverage/abstention 不靠少算坐标伪装变好；
- baseline 稳定性、Unknown rate、missing/gap 行为和已存在的标注指标不回归；
- live/replay shadow 结果可定位到相同 input receipt，无 non-finite；
- 第 19.4 节的 latency、RSS、artifact 和线程预算；
- unsupported profile、artifact 损坏和 backend 失败均安全退回统计 baseline。

只满足无标签 loss 时，候选最多成为新 `selected shadow`。它要影响 `Stable/Changing` 等生产语义，还必须有独立的语义验收集和明确融合/替换规则；该规则不在没有数据时预写。选择在 session 边界通过显式命令完成；旧 digest 仅在 retained session 仍 pin 住时由 managed store 保留，否则回滚需重新提供原 candidate/report 文件并开启新 session。禁止根据最近 live loss 自动选择、自动覆盖文件或在一个 session 中途切换。

这条边界不是放弃持续学习，而是防止 baseline estimator 或 candidate learner 把正在发生的异常持续学成“正常”。

## 20. RF 预训练模型族、部署模型与多模态演化

### 20.1 架构裁决：组合结构，不搬模型动物园

系统采用一个安全统计底座、按 stream 隔离的 candidate/deployment 状态，以及独立的 RF 预训练模型族，不把 RuView 的多个互不相干任务网络、backend 和固定 tensor 搬进来：

| 层 | 位置 | 当前/候选实现 | 权限 |
| --- | --- | --- | --- |
| 统计 estimator | 主机 CPU live | 动态 Welford/EW baseline | 唯一可直接写 production `WorldSnapshot` |
| CPU candidate / 部署路径 | 主机 CPU per stream | 先试 native-coordinate AR(1)；需要神经路径时再试 independently trained frozen encoder + diagonal head，不足时以单向 GRU 替换 | 产生可回放 forecast/candidate evidence；通过准入前只 shadow |
| RF 预训练模型族 | 独立 GPU offline | S/M/L 只表示规模；profile/modality-private adapter + artifact-private episode packing + shared causal dynamics core + task-private heads；MoT 只能在实测负迁移后替换 shared core | 产出预训练 artifact 与评估；可供离线研究、同族缩放/压缩或可选蒸馏，绝不持有 production state |

所谓多个 CPU 实例首先表示同一具体算法或同一 deployment artifact 在不同 `(deployment, link, profile, stream)` 上拥有隔离的 mutable cursor/hidden state，而不是 presence、pose、vitals 各建一套网络。immutable parameter artifact 可以在 compatibility contract 相同的后续 session 复用；profile 真有不同输入语义时可以使用不同 adapter artifact，但相同 shape 不能自动共享；同一 link 的多个 profile 也不能冒充多个空间视角。

```text
live CPU plane
  ConditionedStream
      ├── incumbent baseline ----------------------> production belief
      └── selected candidate/deployment artifact -> StreamForecast (shadow)

offline GPU plane
  sealed sessions -> faithful replay -> native typed facts
      -> concrete profile/modality-private adapters
      -> deterministic artifact-private episode packing
      -> shared causal dynamics core
      -> native forecast/reasoner head
      -> optional offline-only reconstruction/simulation head
      -> PretrainedModelArtifact / EvaluationReport
      -> optional compatible DeploymentModelArtifact
      -> explicit import at a new session boundary
```

GPU trainer 是仓库外的独立进程边界，不是 Rust `gpu` Cargo feature。它只读 sealed/exported session，不能打开 live Engine、writer、baseline pointer 或 selected-shadow sidecar。GPU 训练允许非 bitwise deterministic；部署身份只认输出 artifact bytes digest、训练 manifest 和评估报告。

### 20.2 从头部公开模型吸收什么

| 模型/公开架构来源 | 吸收的结构 | 本项目拒绝照搬 |
| --- | --- | --- |
| [MiniMax H3](https://github.com/MiniMax-AI/MiniMax-H3)、[模型卡](https://huggingface.co/MiniMaxAI/MiniMax-H3)、[许可证](https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE) | modality-private encoder/VAE、统一 packed sequence、共享 Omni Transformer 与 modality-specific I/O 的职责分离；组件 manifest/digest；regeneration 只启发 immutable replay/refinement | 33B dense core、Qwen3-VL-32B、VAE/diffusion/CFG、AdaLN/MM-RoPE、4-GPU runtime；托管且未开放的 Context-IR/Regenerate-2K；Context-IR 补全缺失事实；H3 Community License 的代码、权重或输出在未单独审查时不得成为训练/生产依赖 |
| [MiniMax-M2](https://github.com/MiniMax-AI/MiniMax-M2) | foundation model 与部署角色分离；sparse MoE 把总容量和 active compute 分开，只有观测到目标冲突后才值得做本项目的 expert ablation | 230B total/10B active、agentic/LLM token 与 serving stack 作为 RF 或普通 CPU 可行性证据；foundation checkpoint 不因规模自动成为 teacher |
| [Grok-1](https://github.com/xai-org/grok-1)、[xAI 发布说明](https://x.ai/news/grok-os) | 公开的是 MoE 预训练 base checkpoint；checkpoint 身份与下游 fine-tune、压缩或蒸馏角色分离 | 314B、JAX/Rust runtime、语言 tokenizer、8 experts/每 token 2 active 作为 RF 默认结构；base checkpoint 不自动成为 teacher，也不证明目标 CPU 部署可行 |
| [Cosmos 3](https://research.nvidia.com/labs/cosmos-lab/cosmos3/)、[技术报告](https://arxiv.org/abs/2606.02800) | AR reasoner 与 continuous generator 分塔、共享 omnimodal context；不同能力 surface/规模层级及各自 benchmark | 4B “Edge”作为普通 CPU 可行性证据、reasoner+diffusion 双塔 live、视频/action token、CUDA/Cosmos framework；step distillation 只减少采样步数，不证明小参数 CPU 部署可行 |
| [Qwen3-Omni](https://github.com/QwenLM/Qwen3-Omni)、[技术报告](https://arxiv.org/abs/2509.17765) | modality-private encoder 接共享 Thinker、实际时间对齐、理解与流式生成解耦；先对齐 adapter 再联合训练 | 固定音频时间格、Thinker–Talker、speech codec/multi-codebook、MoE runtime；RF 使用 actual interval/skew/uncertainty，不借用音视频位置语义 |
| [BAGEL](https://github.com/ByteDance-Seed/Bagel)、[论文](https://arxiv.org/abs/2505.14683) | shared context 下按理解/生成目标分离 expert；只有多目标冲突成立时才比较 MoT | VAE/flow matching/二维图像 latent、按硬件 family 建 learned expert/router、把 MoT 当默认架构 |
| [Emu3](https://github.com/baaivision/Emu3)、[Emu3.5 报告](https://arxiv.org/abs/2510.26583) | 单一 causal Transformer + next-token objective 是统一时序建模的可测 ablation | 将连续动态 CSI 量化成公共离散 vocabulary、把所有设备 flatten 为无身份 token、图像/视频生成目标 |
| [Gemma 4](https://blog.google/innovation-and-ai/technology/developers-tools/introducing-gemma-4-12b/)、[技术报告](https://arxiv.org/abs/2607.02770) | raw patch 经轻量 projection 进入 shared core，说明“线性 adapter 是否足够”值得先做消融；variable token budget | 把 12B/16GB 称为本项目 CPU 热路径、因 encoder-free 结果而删除 RF calibration/native-coordinate adapter、LLM/MoE/speculative-decoding runtime |
| [DreamerV3](https://github.com/danijar/dreamerv3)、[论文](https://www.nature.com/articles/s41586-025-08744-2) | RSSM 中 deterministic memory、observation posterior 与 dynamics prior 的职责分离 | action/reward/actor/critic、在线 RL replay、像素 reconstruction 和原 categorical latent |
| [V-JEPA 2](https://github.com/facebookresearch/vjepa2)、[论文](https://arxiv.org/abs/2506.09985)、[V-JEPA 2.1](https://arxiv.org/abs/2603.14482)；[I-JEPA](https://github.com/facebookresearch/ijepa) | context/target encoder、masked/future latent prediction，避免重建硬件噪声；2.1 的 dense/deep prediction 作为 ablation 来源 | 视觉 patch/tubelet、300M—1B ViT/权重、固定图像分辨率和 action-conditioned robot planning |
| [Perceiver IO](https://github.com/google-deepmind/deepmind-research/tree/master/perceiver)、[论文](https://arxiv.org/abs/2107.14795) | variable-length input 通过 cross-attention 汇入 artifact-private latent slots；dynamic output query | 把 latent slot/width 变成领域 schema，或在首个 CPU candidate 引入完整 JAX/Transformer stack |
| [ImageBind](https://github.com/facebookresearch/ImageBind) | modality-specific encoder 映射到共同 representation、各模态 body 不必先统一 | 假定 RF 已与视觉/音频对齐；直接继承 huge model、1024 latent 或 CC-BY-NC 权重/代码 |
| [Mamba](https://github.com/state-spaces/mamba) | causal state carrying 与长序列近线性扩展，是 temporal core 的替换候选 | 当前 PyTorch/CUDA selective-scan stack、固定 `d_model` 公共化，或与 GRU/RSSM 并存两套 core |

“Edge”不是普通 CPU 结论。Cosmos3-Edge 的官方目标硬件是 Jetson/RTX GPU；公开的 15 Hz 是特定 action-policy surface，reasoner 与 generator 有不同成本。[官方模型矩阵](https://docs.nvidia.com/cosmos/latest/cosmos3/model_matrix.html)与[官方推理基准](https://github.com/NVIDIA/cosmos/blob/main/inference_benchmarks.md)都不能替代本项目第 19.4 节的整机 CSI workload 测量。其 diffusion step distillation 也没有证明本项目目标 CPU 上的小参数部署模型可行。

这些公开项目支持的是一个**功能分解**，不是某个现成 backbone，也没有把 foundation/pretrained checkpoint 定义成长期 teacher：native facts 由 concrete private adapter 编码，确定性 episode pack 保留身份/时间/mask/receipt，shared causal core 建模共同动力学，task-private head 再输出 native-coordinate forecast；可选 generator 只在 offline 做 reconstruction/simulation。首个 shared core 使用最简单的单一 dense/causal 路径；只有同一训练集上出现可复现的多模态或多目标负迁移，MoT/experts 才能作为它的**替换**实验，不能并存成模型动物园。

实际升级顺序仍固定：AR(1) → 单 profile RF 预训练模型 spike → 独立训练的 CPU 部署候选 → 必要时比较量化、剪枝或同族缩放 → 只有直接部署路径不足且预训练模型显著更好时才试蒸馏 → 有同步多 link/第二 modality 数据后才试 artifact-private early/mid fusion → 测得目标冲突后才比较 MoT → 长序列成为瓶颈后才比较 Mamba。任一步无 independent holdout 收益就停止。H3、Cosmos 等公开模型只提供边界证据；其权重、输出、许可与运行时不进入默认训练或生产路径。

### 20.3 CPU candidate 与部署模型的稳定边界

第一个 candidate 是第 19 节的 AR(1) 算法，不把它称为神经模型。只有它在相同 `CandidateInput` 上的 forecast tail error 明确不足，才先试第 19.2 节独立训练的 frozen encoder + diagonal head。该路径也不足时，才以一个单层单向 GRU 部署候选**替换**它；同一 session 只允许一个 neural CPU artifact，hidden width 属于 artifact，不是系统配置或公共 schema：

```text
one ConditionedStream + incumbent evidence
    -> artifact-private coordinate encoder/pooling
    -> diagonal one-step head
       or, only as its replacement, causal GRU state
    -> native-coordinate next-window forecast
```

- mutable state 按 `(SessionId, StreamId, ArtifactDigest)` 隔离；session/HostEpoch/profile/artifact、conditioning/baseline/window contract 或 BaselineRevision 改变，以及 gap、shadow skip、rejected input、predecessor mismatch 都立即 reset。immutable parameter artifact 仍可在 compatibility contract 相同的 session 间复用。
- hidden state 不持久化；live/replay 都从 pinned session 输入重算。
- CPU 部署模型不做 learned cross-link fusion；production room state 仍走第 12 节的保守规则。
- unsupported profile、token budget overflow、non-finite、backend/deadline failure 一律 abstain 并退回统计底座。
- CPU 部署模型与 RF 预训练模型不要求共享 latent shape、hidden state 或 backend API；只共享下面的可审计 forecast 语义。

未来神经候选模块私有的最小输出是：

```rust
struct StreamForecast {
    input: CandidateInputId,
    forecast_contract: ForecastContractId,
    horizon: TimeInterval,
    coordinates: BTreeMap<NativeCoordinateKey, PointForecast>,
    artifact_digest: ArtifactDigest,
}

enum PointForecast {
    Available { standardized_residual: f64, support_windows: u32 },
    Abstained { reason: CandidateExclusion },
}
```

`ForecastContractId` 使用第 19.2 节定义的共享 residual 预测合同。`NativeCoordinateKey = (CsiPath, CsiSampleCoordinate)`；首个 `PointForecast` 只含预测值、support/abstention，不在无校准数据时增加 variance、confidence 或 semantic probability。`StreamForecast` 与这些类型都在 neural candidate 真正进入 spike 时才作为 `candidate` 私有值实现，不替换 raw/session/domain 的 `CsiCapture`；AR 切片继续使用其具体逐坐标预测结果，不提前实现这组 future structs。

### 20.4 RF 预训练模型的最小 coherent topology

多模态 RF 预训练模型族的长期边界是：

```text
RF / future modality native typed facts
    -> concrete profile/modality-private continuous adapter
    -> deterministic artifact-private EpisodePack
    -> one shared causal dynamics core
    -> native-coordinate forecast/reasoner head        [required]
    -> masked latent consistency head                  [training only]
    -> reconstruction/simulation generator            [optional, offline only]
    -> PretrainedModelArtifact / CandidateEvidence     [never WorldSnapshot]
```

`EpisodePack` 不是新的 domain 类型、公共 token schema 或第二事实源。它是 trainer 根据 artifact recipe 从 `CandidateInput` 临时派生的私有值，稳定保留 profile、link/path、native coordinate、实际 interval/delta、time uncertainty、quality、mask、source receipt、排序和 overflow receipt。它不能像生成模型的 Context-IR 那样推断或补写缺失语义；unknown/missing/unsupported 必须仍然显式。第二种真实 modality 到来前，不实现通用 codec trait、modality enum、packer registry 或 `EpisodePack` Rust 类型。

第一个 GPU 预训练 spike 仍只做单个 `ConditionedStream`：以一个 concrete profile-private continuous adapter 产生 context/target token，用 masked-coordinate 和 future-window latent prediction 学习；mask 与 future horizon 都是 training receipt 的输入。Gemma-style linear projection 是 adapter 的第一个廉价 ablation，但只有在不丢失 native axes/receipt 且同一 forecast holdout 不劣于专用 encoder 时才保留。VQ/discrete vocabulary 只有在 native-coordinate reconstruction、forecast 和跨设备 holdout 都证明无损后才可研究。

shared core 默认是一条 dense causal path，并在各 stream 间共享 immutable parameters；mutable state 仍按 link/profile/source epoch 隔离。adapter 由 `CaptureProfileId` 确定性选择，禁止 learned hardware-family router，以免把设备指纹误当跨设备语义。它必须同时输出 native-coordinate forecast probe，不能只凭 latent、reconstruction 或 next-token loss 晋升。

有证据需要更长状态后，temporal core 才采用 RSSM 的职责分工：

```text
h_t       = deterministic causal memory before observation t
prior     = p(z_t | h_t)
posterior = q(z_t | h_t, encoded stream_t)
h_t+1     = transition(h_t, z_t, actual delta_t)
```

这里只借用 prior/posterior/causal memory，不存在 action、reward、actor、critic 或 imagined control rollout。posterior 只能看 context cutoff 以内的观测；future target 不得进入 encoder state。

只有取得同步、多 link/多 modality、同一物理 episode 且拓扑/时间已校准的 corpus 后，offline 预训练才允许把多个 concrete adapter 的 token 放入同一 `EpisodePack`，比较 permutation-invariant pooling、Perceiver-style dynamic-set fusion 或 shared-core early/mid fusion。输入仍按物理 `RadioLinkId`/native source 分组，同一 link 的多个 profile 仍是一组；包内身份不会因排序或缺 source 改变。普通异步 ESP32 不能套用 WiFi-JEPA 固定九 link 的同步假设。

若 forecast/reasoning 与 reconstruction/generation 的梯度冲突或 holdout 负迁移被实测复现，才以 BAGEL/Cosmos-style objective-specific MoT 替换相关 shared-core block；不按硬件建 expert，不同时保留 dense 与 MoT 两套生产 core。forecast/reasoner surface 与 generator surface 使用不同 head、loss、artifact role 和性能报告。generator 只用于 sealed-session offline 预训练研究、数据消融或模拟，不能把 action、解释文本或 synthetic observation 写回 raw/session/world；系统没有真实 action source 前也不存在 action token/head。

Mamba/SSM 只在 profiler 证明 recurrent core 的长序列吞吐/记忆是瓶颈时作为**替换** spike，不是第二套并存 backend。Cosmos 类 video generator、VLM reasoning head 和自然语言解释不进入 RF 生产推理。

### 20.5 动态设备、representation identity 与私有 fusion contract

固定内部维度不是错误；把它泄漏为全系统 `56 × 8` 才是错误。每个具体 artifact 可以固定 `d_model`、latent slots 和 token budget，但必须私有并带 mask/overflow receipt。

未来拿到第一个真实 encoder 后，`candidate.rs` 内部可以实现以下具体值；第一切片不创建 public trait 或这些 future structs：

```rust
struct EncodedStream {
    representation_contract: RepresentationContractId,
    adapter_digest: ArtifactDigest,
    link_profile: LinkProfileKey,
    interval: TimeInterval,
    time_quality: TimeQuality,
    coordinate_mask_digest: Digest,
    values: Vec<f32>,
    input: CandidateInputId,
}

struct EncodedLink {
    link: RadioLinkId,
    profiles: Vec<EncodedStream>,
    topology: Option<TopologyCalibrationReceipt>,
}

struct SharedCandidateInput {
    deployment: DeploymentId,
    space: SpaceId,
    window: WindowId,
    alignment: AlignmentReceipt,
    links: Vec<EncodedLink>,
    missing_links: Vec<RadioLinkId>,
}

struct CandidateEvidence {
    target_space: SpaceId,
    interval: TimeInterval,
    knowledge: Knowledge<CandidateSemantic>,
    contributions: Vec<CandidateInputId>,
    exclusions: Vec<CandidateExclusion>,
    artifact_digest: ArtifactDigest,
}
```

`RepresentationContractId` 绑定 feature/conditioning recipe、coordinate/mask semantics、training objective/version、representation family、normalization 和 numeric precision。两个 adapter 都输出相同长度不代表合同相同；ESP32 与 Intel 只有经过联合对齐训练，并在每种已支持硬件上通过 leave-device-instance/profile/room/session-out holdout 后才可共享 ID。只有声称支持训练中从未出现的新 hardware family 时，才额外要求 leave-hardware-family-out。

约束：

- 每个 token 保留 link/profile、`CsiPath`、native coordinate、interval/actual delta-t、time quality、validity 和 source receipt。
- `OpaqueSampleOrdinal` 不跨 profile/hardware 自动对齐；未来有真实 tone/frequency 语义也仍保留 path。
- 输入 link 顺序不得影响 fusion；missing/unsupported link 是显式 mask/exclusion，不是零 token。
- 几何只有携带 `TopologyCalibrationId` 才可进入 positional encoding，不能从设备数组顺序伪造。
- fusion artifact manifest 逐项声明 `(CaptureProfileId, adapter_digest) -> accepted RepresentationContractId`；不同硬件 adapter digest 可以不同，未列入 mapping 或 representation contract 不同才 abstain。
- learned fusion 另声明 time source、maximum inter-link skew/uncertainty 和 alignment policy；`AlignmentReceipt` 记录实际来源、区间和误差，超限必须 abstain。`TopologyCalibrationId` 不能替代时间对齐证据。
- artifact 声明最大 stream/coordinate/token budget 和 overflow policy；超限明确 abstain，或采用带 receipt 的确定性裁剪，禁止静默 truncate。
- RF 预训练模型和部署模型只能产生 `CandidateEvidence`，不能直接构造、覆盖或持有 `WorldSnapshot`。

### 20.6 live 晚融合，offline 预训练有条件 early/mid fusion

当前只有 RF typed facts，不预建 `Modality::Camera | Lidar | UWB | Custom`。第二种真实 modality 到来时新增其具体 native observation、事实源和 concrete adapter；共同字段只有 identity、space、interval/time uncertainty、quality、provenance 和 artifact receipt，measurement body 保持 modality-specific。

```text
live CPU safety plane
  RF native facts ------> RF typed evidence ----┐
  future IMU facts -----> IMU typed evidence ---├-> space/time belief fusion
  future vision facts --> vision typed evidence ┘

offline pretraining plane, only with paired/aligned corpus
  modality-native facts -> concrete private adapters
      -> deterministic EpisodePack + AlignmentReceipt
      -> one shared causal core / dynamic-set fusion
      -> task-private candidate heads
```

首个 live 路径始终从 typed evidence 晚融合，因为它能独立 abstain、回放和退回统计底座。learned packing 属于一个具体 offline fusion artifact，不属于 domain/session。只有 paired episode、同步/对齐 receipt、每种 source 的独立 holdout 和 device/profile shortcut probe 都存在时，才允许不同 modality 进入 shared representation；否则仍在 evidence/world 层晚融合 `Knowledge + contribution + exclusion`。

通过 offline gate 不等于 RF 预训练 artifact 可直接 live。部署路径可以是独立训练的小规模同族模型、对兼容架构做量化/剪枝/结构化压缩，或在必要时做蒸馏；任何路径都必须以相同 `CandidateInput`/`ForecastContractId` 通过目标 CPU 门禁。这个边界吸收了多模态模型的共享上下文思想，同时拒绝 RuView 预枚举万能 modality、用 `unit + dimensions` 抹掉物理轴、再在训练侧另行 reshape 成固定图片。

### 20.7 训练因果性、数据泄漏、部署与可选压缩

每个训练 example 的 receipt 必须固定：

```text
context record/session/window ranges + context cutoff
masked coordinates/links/modalities + mask seed/algorithm
target interval + prediction horizon
all contributing profile/topology/representation contracts
ExampleGroup: deployment + space + physical episode/interval
```

- 同一物理 episode/同步 interval 的所有 links、profiles 和未来 modalities 原子进入同一 split。
- split 在 baseline fit、normalization、windowing、mask/augmentation 和 positive/negative sampling 前完成。
- overlapping windows、reciprocal pair、multiview scene 不跨 split；test 不参与 checkpoint/model selection。
- GPU trainer 从 sealed session faithful replay 产生 length-delimited ephemeral examples；可删除 cache 必须带原 session/window receipt，不能成为第二事实源。
- `PretrainedModelArtifact` 只含实际存在的 immutable concrete adapters、input/packing recipe、shared core、forecast/reasoner head、可选 generator head、各自 manifest 与 digests；它只能用于 sealed-session offline replay/evaluation，不是 `ShadowSelectionPin` 的合法 candidate。没有真实多组件 artifact 时不预建 bundle loader/registry。
- `DeploymentModelArtifact` 独立训练和评估，不覆盖预训练 artifact 或 production baseline；两者只共享 `CandidateInput`、`ForecastContractId`、native-coordinate target、support/abstention 和 source receipt，不要求共享 latent width、token shape、hidden state 或 backend。
- 允许的部署路线只有：独立训练目标 CPU 模型；对兼容架构量化、剪枝或结构化压缩；可选 output distillation。路线是实验选择，不预建统一压缩框架。
- teacher/student 只是一份蒸馏实验报告中的临时角色。该报告必须在同一 split 上比较 AR incumbent、相同部署架构不使用预训练输出的训练结果、相同部署架构使用蒸馏的结果；第三者未显著优于前两者时删除蒸馏路径。真实 next-window residual 始终是主 target，soft forecast 只能是辅助 target。
- 只有通过目标 CPU 门禁的 `DeploymentModelArtifact + CandidateEvaluationReport` 才能导入 live session。
- time-forward 与 leave-device/link/room/person holdout 分开报告；使用 target 无标签数据只能称 target self-supervised adaptation，不能称 zero-shot。

没有独立 semantic ground truth 前，RF 预训练模型最多是 **offline pretrained candidate**；self-supervised/forecast 改善不能让它获得 production world gate。演化闭环的控制点仍是 artifact、`EvaluationReport` 和 session-boundary explicit selection，不是 online weight mutation。

## 21. 对 RuView、RF 文献与开源模型的裁决

来源是证据，不是权威。以下裁决经过协议/产品、Rust 落地、文献需求、CPU 性能和开源模型结构对抗审阅后做了首个切片过滤。

| 来源 | 可吸收 | 首个切片拒绝/延后 |
| --- | --- | --- |
| RuView ADR-018/firmware/actual code | wire 常量、sibling packet 分类、严格边界 fixture、原始 complex bytes、running EW statistics 思路 | `56 × 8`、错误 `[I,Q]`/假 tone 语义、任意 rank tensor、重复 parser/全局 lock/假 UI；`sensing-server/src/trainer.rs:800-936` 与 `wifi-densepose-train/src/rapid_adapt.rs:178-240` 对全参数 central finite differences；`wifi-densepose-nn/benches/inference_bench.rs:30-100` 是 MockBackend；`main.rs:7834-7864` 吞掉具体 load error、只打印通用提示并自动退 synthetic/56；并存 Burn/tch/Candle/ORT |
| RuView HAL/ontology/training schema | 设备能力与 measurement schema 应显式、训练输入必须有版本和 receipt | `ruview-hal/src/modality.rs` 预枚举 CSI/BLE/UWB/mmWave/camera/lidar/IMU 的万能 modality；只用 `unit + dimensions` 丢失物理轴；ontology observation 不携带真实 measurement；训练侧把 CSI 另行 reshape 为 `[B,3,48,48]` |
| [ESP-IDF Wi-Fi CSI contract](https://github.com/espressif/esp-idf/blob/master/docs/en/api-guides/wifi-driver/wifi-vendor-features.rst) | `[imaginary, real]` 顺序、first-word validity、LTF/acquire 配置决定 buffer 语义 | 把 ADR 的 pair count 无条件叫物理 subcarrier，或继承 RuView 的 `[I,Q]` 解析 |
| [The Universal Language of CSI](https://arxiv.org/abs/2607.09727) / [WiLLM](https://github.com/cjychenjiayi/WiLLM)，Zotero `SNQMXYRW` | device/dataset-specific frontend 与 shared representation 分层值得验证 | amplitude-only dataset adapter、固定 latent、dataset CNN/Transformer 作为运行时契约；该工作未替本系统解决 live mixed-device time/link fusion、baseline 污染、uncertainty 和 replay |
| OpenCSI，Zotero `2L4VHI3X` | per-link baseline、maturity/reliability、校准状态、低成熟度 abstain、packet-rate 分桶 | 把单一 Z-score 或论文固定秒数/阈值当作所有设备通用常数 |
| CSI-Bench，Zotero `FULL46UK`；data-leakage review `XMUTVCW4` | manifest、按 deployment/session/device 分组、split-before-window/preprocess | 随机 frame split、同场景少标签结果冒充跨环境泛化 |
| CSI sampling nonuniformity `J53NH6F7` | actual timestamp/delta-t、rate/jitter 成为质量上下文 | sample index × 假定 FPS |
| [Espressif esp-csi](https://github.com/espressif/esp-csi)、[CSIKit](https://github.com/Gi-z/CSIKit)、[pyespargos](https://github.com/ESPARGOS/pyespargos) | 用真实采集工具和多 chipset reader 建 fixture/corpus；coherence 是显式 hardware capability | 把工具内部 matrix 当领域 schema；没有共同 clock/LO/calibration receipt 的相干 phase fusion |
| [Widar 3.0](https://tns.thss.tsinghua.edu.cn/widar3.0/index.html)，Zotero `EZCVW6XP` | 几何、Doppler/BVP 是有足够多 link 和 ground truth 后的候选 | 把 gesture/pose/BVP 塞入首个房间变化切片 |
| [WiFi-JEPA](https://arxiv.org/abs/2607.11064)，Zotero `I4KFVKE2` | 吸收 masked latent/link prediction；native-coordinate forecast probe 是本项目额外准入要求 | 其同步固定 link tensor/pose 数据假设不能套到异步 ESP32；九 link 不是系统常量 |
| [AM-FM](https://arxiv.org/abs/2602.11200)，Zotero `XZSP43BE` | 大规模无标签预训练、多个 SSL objective 和较小下游模型值得做离线 pretraining spike | 论文的 amplitude preprocessing 与 `1 × 500 × 112` padding/truncation 不能进入领域/session contract |
| [CAPC](https://github.com/bornabr/CAPC)，Zotero `2R24BJAV` | 从当前 context embedding 预测 future-window latent、冻结 encoder 后评估 transfer | uplink/downlink 只能在同步、互易与 coherence 条件有 receipt 时作为 positive pair，不能按名称假设互易 |
| [DATTA](https://arxiv.org/abs/2411.13284)，Zotero `SEEFUF22` | 轻量部署适应可作为 closed-session candidate 的研究输入 | production test-time weight mutation、无 immutable artifact/holdout 的自更新 |
| [ONNX Runtime CPU/Execution Providers](https://onnxruntime.ai/docs/execution-providers/)、[on-device training](https://onnxruntime.ai/docs/get-started/training-on-device.html) | 证明离线生成训练 artifact、CPU inference/训练在工具链上可行 | 工具可用不等于本项目候选达标；[默认线程](https://onnxruntime.ai/docs/performance/tune-performance/threading.html)可能占满物理核，[INT8](https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html)可能变慢，CPU 不采用 [FP16](https://onnxruntime.ai/docs/performance/model-optimizations/float16.html) |

指定论文证明“跨数据集共享 representation 值得研究”，没有证明某个固定 latent 或 amplitude preprocessing 应成为 RF 领域合同。官方 runtime 文档只证明 CPU 路径存在，也没有证明任意 pretrained model 会满足本机 deadline。本文档因此以原生动态坐标 AR(1) 做第一个 CPU 自监督候选；冻结 encoder + diagonal head 只有拿到真实 artifact 后才进入实测，拒绝先实现 foundation model 框架。

## 22. 开发准入测试

以下测试全部通过后，首个切片的内核才算完成；它们也是实现拆任务的验收合同。

### 22.1 parser 与事实源

1. ADR-018 64/128/256 等真实动态长度 fixture 均保留原始 opaque sample 数量；测试数字是 fixture，不是领域常量。
2. 对每个合法 datagram 的所有截断前缀调用 decoder，均返回错误且不 panic。
3. 零维度、超大维度、乘法溢出、错误 payload 长度和 trailing bytes 被拒绝。
4. unsupported sibling magic 与 malformed packet 分类不同。
5. parser 修改后可从 `CapturedPacket` 重新解释旧 session；原 wire bytes 不变。

### 22.2 身份、timeline 与多设备

6. 同一 `node_id` 来自不同 peer 时按配置隔离或拒绝，不能串 baseline。
7. 两个设备相同 sequence 互不影响。
8. wrap、gap、duplicate、reorder 和 probable restart 各有确定结果。
9. node sequence `1,2,3` 对应交错 profile A/B/A 时 source 无 gap，profile B 不伪造缺帧。
10. inactive stream 不永久卡住 global watermark；无 packet 的已发布窗口可由 `TimelineAdvance` replay。
11. late/missing 形成明确 gap/`None`，绝不变成零 I/Q。
12. 两种 profile 同时存在时独立窗口、baseline、查询和显示，不丢“较稀”布局。
13. 未声明 HE tagging 时 bytes 18..19 不被解释；frequency 按 MHz checked 转 Hz；ADR path 永远是 RawPathOrdinal，sample axis 永远是 OpaqueSampleOrdinal。
14. ADR `[Im,Re]` 映射为 `q=first/i=second`，前两个 pair 被排除；缺 frame-validity 的 C6 dialect inference-ineligible。
15. 相同 bytes/count 但不同 LTF selection/merge 或 validity dialect 生成不同 ProfileId，拒绝 baseline 复用。
16. 未 provision 单一 transmitter 的 route 为 UnresolvedSource，不能进入 baseline；channel policy mismatch 被拒绝。

### 22.3 baseline、world 与 replay

17. 未 Commit 的 Learning baseline 只能输出 Unknown；未 ready coordinate 不参与 Commit。
18. high deviation、low quality、stale、frozen 和 incompatible profile 不改变 Active baseline。
19. 两个 accepted window 之间的长 gap 不增加 learning exposure；恢复后的首窗不 EW update，下一窗 alpha 只由本窗有效 exposure 决定。
20. baseline command（含 ActivateSnapshot 完整 payload）写入 session；replay 后 revision/state sequence 一致。
21. 两个 link 的 state 独立，space state 保存全部 contribution/exclusion；同一 link 的两个 profile 只算一个 coverage link。
22. 两 sensors × 两 profiles 的同一 global window 只生成一个 SnapshotId，输入 stream 顺序不改变结果。
23. 无 eligible link 为 `Unknown::InsufficientCoverage`；中间阈值为 `Unknown::AmbiguousEvidence`。
24. live 与 faithful replay 在同 build/target 下的 typed semantic snapshots 完全相等。

### 22.4 session、API 与 UI

25. session roundtrip、长度上限、record_seq、CRC 损坏、截断尾部 recovery-seal 和 rotation 均有测试；monotonic time 重置后 session-local timer/armed state 重置，rotation live/replay 等价。
26. append/flush 失败停止 capture；view queue 满只影响 delivery 并有指标。
27. oversized UDP datagram 被完整接收后明确拒绝，不能伪装成普通 truncated packet。
28. SignalView 同时查询不同 sample-coordinate 数，返回各自原生语义。
29. viewport 聚合保留 min/max/mean/RMS/count 和 missing span；phase 超预算拒绝而非线性聚合。
30. snapshot evidence 返回 exact coordinate mask/observed/predicted/residual 和 baseline state sequence。
31. UI 不默认首节点、不取模复制数据、不把 opaque ordinal 伪造为 tone/MHz/空间坐标。
32. live 断开显示 disconnected，不生成 synthetic world state。
33. 内存构造的 Intel `3 × 3 × 30` CSI 通过核心和 view；Intel capture 配置明确报 unsupported。
34. 全仓库检查不得在 domain/session/API/UI 中出现权威 `56`、固定 `64` 或固定 snapshot 数。

### 22.5 CPU 自监督与性能

第 1—34 项完成最小内核；宣称“CPU 可自监督演化”前还必须通过：

35. AR state 按 native dynamic coordinate key 隔离；将来的 frozen encoder packing 保持 artifact 私有，领域/session/API/UI 不出现 latent 或固定模型 input shape。
36. `learn-ar1` 拒绝 live/unsealed session、跨 gap/profile/epoch/baseline-revision pair 和 train/holdout 重叠；相同输入与配置产生相同 AR artifact digest。
37. AR artifact/evaluation report 以及将来的 encoder/head 损坏、report 指向错误 candidate digest、不兼容 profile、non-finite 输出和 backend error 均不污染 baseline，并产生明确 fallback/shadow skip receipt。
38. 目标主机分别通过 30 分钟 packet-bound 与 byte-bound harness：前者逐 route 达 `2 × peak_packets_per_second`，后者用真实 maximum-size fixture 达 aggregate `2 × B_peak`；两者 durable append 的新增 application/kernel drop、write failure、decoder failure 和未解释 sequence gap 为 0，并记录逐 route/aggregate achieved rate。
39. `1×` capture + 查询 + shadow 的 P99 不超过 `min(snapshot_deadline, 0.5 × T_step)`，RSS、线程和 artifact size 满足填写过的 budget。
40. faithful replay 分别对 packet-bound 与 byte-bound corpus 达到对应 `2×` 声明 workload，并报告 achieved pps/bytes/s 以及 read/decode/condition/baseline/candidate stage；不能从单一平均 payload 外推另一负载。
41. 单 worker `learn-ar1` 吞吐不低于 eligible 数据产生速度，RSS 有界且训练/输出无 NaN/Inf。
42. shadow on/off 对相同 input 的 production semantic projection 完全相同，开启后的 P99 不超过 `1.10 × L_no_shadow` 且满足绝对 deadline；capture 与 learner 争用 runtime lock 时一方明确拒绝。
43. shadow 跳帧后下一 input 的 predecessor mismatch 会清 cursor；live 压力按 DisableShadow、ReduceViews、StatisticalOnly 转换，不丢 raw。
44. frozen encoder 到来后 FP32 与任何 INT8 候选分别实测；量化未改善 latency/RSS 或产生质量回归时仍选 FP32。
45. capture active 时 shadow 选择/回滚被拒绝；停止后选择只对新 session 生效，candidate/report 两个 pin 随 session export/retention/replay；所有 managed-data replay/export/import/GC 与 capture 争用同一 runtime lock 时一方明确拒绝；无标签 loss 不能启用生产语义。
46. 至少跨两次 rotation 的 soak 中 learning lag、RSS、queue 和 artifact 数量受 retention 上限约束；GC 不删除 retained manifest 的 pin，rotation 后 baseline adaptation 行为与 faithful replay 一致。
47. rotation 改变 BaselineRevision 但不改变 BaselineContractId 时旧 artifact 仍命中；新 session/ProbableRestart 后首个 eligible input 只 seed cursor，Stale 时 abstain。
48. Intel `3 × 3 × 30` evidence 生成 270 个不同 `(CsiPath, coordinate)` parameter key；不得把九条 path 合并。
49. residual、gate、eligibility 或 WindowContract 任一字段改变都会产生新 contract ID 并拒绝旧 artifact。
50. 坐标 A 在中间 eligible 窗 missing、坐标 B 持续有效时，A 恢复后的首窗只能 seed，B 仍可配 pair；coordinates/input 的稳定排序和无重复构造校验失败时拒绝。

### 22.6 预训练模型、部署模型与多模态的未来准入

以下项目不阻塞首个开发切片，但实现对应能力前必须通过；它们防止“参考多模态”退化成另一个固定 tensor 或模型框架：

51. 两条 shape 完全相同但 `RadioLinkId` 不同的 stream 不共享 local state；同一物理 link 的多个 profile 不增加 world coverage link 数。
52. artifact 的固定 `d_model`/slot/token budget 只存在于私有 manifest 与 packing；domain/session/API/UI 不出现 latent shape。
53. fusion manifest 必须将每个 `(CaptureProfileId, adapter_digest)` 映射到接受的 `RepresentationContractId`；未列入的 adapter、representation contract/topology/numeric precision 不兼容时明确 abstain，不能因 digest 或输出长度相同而融合。
54. 打乱 link/profile 输入顺序不改变 fusion evidence；missing link 不会使剩余 token 重新获得别的物理身份。
55. `OpaqueSampleOrdinal` 不跨 profile/hardware 对齐；ESP32 与 Intel adapter 只有经过联合对齐训练，并在每种已支持硬件上通过 leave-device-instance/profile/room/session-out holdout，才能声明同一 representation contract；声称泛化到未训练 hardware family 时才额外做 leave-hardware-family-out。
56. 超过 stream/coordinate/token budget 时按 artifact policy 确定性拒绝或裁剪，并记录完整 receipt；不能静默 truncate/pad。
57. context cutoff 之后的 record、masked target 和 future interval 不得进入 causal encoder state；同一同步 episode 的所有 links/profiles/modalities 原子进入一个 split。inter-link skew/uncertainty 超过 fusion manifest 门限时不能进入 learned fusion。
58. RF 预训练模型 candidate 必须输出动态 native-coordinate forecast、support/abstention/exclusion 和 source receipt；只改善 latent/reconstruction loss 不具备晋升资格，uncertainty 只有校准后才可增加。
59. RF 预训练模型和部署模型都不能写 `WorldSnapshot`；artifact 缺失、backend error 或 non-finite 输出时 production baseline 语义不变。
60. 对每个固定 CPU deployment artifact，live/replay 使用相同语义候选输入和 pin 后产生相等 `CandidateEvidence`；预训练与部署 artifact 共享 `CandidateInput`/`ForecastContractId` 时才可比较，部署 artifact 按 manifest tolerance、coverage 和 abstention 独立评估，不要求与预训练 artifact bitwise 相等。
61. session/profile/artifact、conditioning/baseline/window contract/revision、gap、shadow skip、rejected input 或 predecessor mismatch 都清 recurrent state；immutable parameters 只有 compatibility contract 相同才可跨 session 复用。
62. synchronized/calibrated multi-link corpus 不存在时，代码中不得实现 learned cross-link fusion；第二种真实 modality 不存在时，不得创建通用 modality enum 或 multimodal adapter。
63. 一个 RF 预训练模型可以独立存在，不要求蒸馏或部署。只有统计 baseline 与 AR 在目标合同上不足时，才允许一个 independently trained、量化/剪枝/结构化压缩或蒸馏得到的 CPU deployment artifact 进入准入；它必须通过适用的 artifact integrity、整组 stream 性能、fallback、session-boundary 和 replay gate，recurrent 路径另测 causal reset/determinism，任何 CPU learner 另测吞吐/RSS。
64. 相同 native facts 与 packing recipe 必须产生稳定排序、稳定摘要的 EpisodePack；unknown、missing、unsupported source 和超预算输入保持显式 mask/exclusion/overflow receipt，packer 不得补写或生成观测事实。
65. 每个 packed element 保留 source/profile/link/path、native coordinate、actual interval/delta、time uncertainty、quality、mask 和 source receipt；相同 packed width、token count 或 adapter output length 不构成 representation compatibility。
66. adapter 必须由 `CaptureProfileId` 确定性选择，禁止 learned hardware-family router；连续动态 token 是默认，VQ/discrete vocabulary 只有同时通过 native-coordinate reconstruction、forecast 与跨设备 holdout 才可替换。
67. shared pretrained core 首先只有一条 dense causal path。MoT/expert 只有在同一 split 上复现多 modality/objective 梯度冲突或 holdout 负迁移后才能替换相关 block；不能按设备建 expert，也不能并存 dense/MoT 两套 production core。
68. native-coordinate forecast/reasoner head 是必备晋升 surface；reconstruction/simulation generator 有独立 artifact role 且只限 offline，不能进入 CPU live、写 raw/session/`WorldSnapshot`，没有真实 action source 时不得出现 action token/head。
69. Gemma-style linear adapter 只能作为 artifact-private ablation；它必须保持同一 `ForecastContractId`、全部物理轴与 receipt，并在相同 holdout 上不劣于专用 adapter，不能因投影后 shape 可用而晋升。
70. output distillation 只是可选实验；teacher/student 仅是报告内临时角色，不得成为模块、服务、类型或 artifact 名。实验在同一 split 比较 AR incumbent、相同部署架构不使用预训练输出、相同部署架构使用蒸馏；三者共享 `CandidateInput`、native forecast target 和 `ForecastContractId`，但不得要求共享 latent/token/backend。soft target 不能替代真实 next-window target，第三者未显著更好时删除蒸馏路径。
71. MiniMax H3、Cosmos、Qwen、BAGEL、Emu、Gemma 等外部代码、权重、输出、服务和 runtime 都不是生产或训练依赖；引入前必须分别通过许可、数据来源、artifact、CPU/质量 gate。H3 的代码/权重/输出在单独许可证审查前不得用于本项目训练或蒸馏。

## 23. 实现顺序

顺序按风险从事实边界向外推进，不先搭空 UI 或模型框架：

1. `domain + config`：ID、Registry、CsiLayout/CaptureProfile 构造校验和 Intel 形状内存测试。
2. `capture + session + esp32`：字节记录、唯一 dispatcher、fixtures、CRC/recovery、capture/replay CLI。
3. `timeline`：profile partition、sequence/epoch、watermark、window、gap 和 actual delta-t。
4. `conditioning + estimator + engine`：显式 receipt、EW prediction、gate、baseline command、world aggregation、deterministic replay。
5. `view + server + web`：先完成动态 SignalView contract，再做一页二维诊断 UI。
6. 端到端多 ESP32 soak/replay：磁盘吞吐、UDP gap、慢 WS、restart 和 baseline poisoning。
7. 在声明的参考 CPU 上建立统计 estimator 性能事实；加入具体 `candidate.rs`，实现 native-coordinate AR(1)、closed-session `learn-ar1/evaluate-candidate`、artifact 和 bounded shadow，不添加 ML runtime。
8. 通过 AR candidate 的 time-forward holdout、deterministic replay、shadow 干扰、rotation/learning-lag、runtime-lock 排他和 shadow 选择/回滚准入。
9. 只有积累足够 sealed ESP32 corpus 后，才在外部 GPU 进程做单 profile RF 预训练模型 spike；它使用一个 concrete continuous adapter、一条 shared causal core 和 native-coordinate forecast head，产出 `PretrainedModelArtifact` 与独立评估，不先实现 `EpisodePack`/MoT/generator，也不给 Rust 增加 GPU feature 或训练框架。
10. 只有统计 baseline 与 AR 不足时，才先独立训练一个 frozen encoder + diagonal head CPU deployment candidate；再按实测需要比较同族缩放、量化、剪枝或结构化压缩。只有 RF 预训练模型显著更好、直接部署路径不足且蒸馏使同一部署架构显著改善时才保留 output distillation。该部署候选仍不足时才以单层单向 GRU 替换。任一路径不达第 19.4 节预算就停止，同一 session 只加入一个具体 deployment artifact/backend，不建立 trait/registry。
11. 只有拿到同步、同 episode、多 link 且有 `TopologyCalibrationId`/`AlignmentReceipt` 的 corpus 后，才实现 artifact-private EpisodePack 并按最小 holdout spike permutation-invariant dynamic-set fusion；Perceiver 只是 cross-attention 候选，不是预定依赖。否则继续 per-link temporal candidate + world evidence 聚合。
12. 第二种真实 modality 到来后才新增其 native facts 与 concrete adapter，并先做 typed late fusion；具备 paired/aligned corpus 后才在 offline pretraining 比较 shared-core early/mid fusion，只有实测 objective 负迁移才以 MoT 替换相关 block。有独立语义验收集后才能设计 candidate 如何影响 production belief。

第 1—6 步是最小内核，第 7—8 步是同一架构上的纯 CPU 演化切片，第 9—10 步是可选 RF pretraining/deployment 增强，第 11—12 步由真实同步数据和第二 modality 触发；都不复制 `v2` 目录或领域类型。后一步不得反向把 HTTP、UI、硬件或神经模型私有 shape 塞进前一层。

## 24. 明确延后与升级门槛

### 24.1 有数据再做

- Intel 5300 真实 decoder 与混合硬件 soak；
- 固件 stable hardware/boot/TX identity 和 per-frame capture ticks；
- phase calibration、clock mapping 和 coherent fusion；
- ground-truth 校准的 presence/motion/OOD；
- candidate 对 production belief 的融合/替换规则和语义晋升；
- RF 预训练模型族、CPU 部署模型、可选压缩/蒸馏、RSSM temporal core、artifact-private `EpisodePack` 与 learned multi-link/multimodal fusion；
- `RepresentationContractId`/encoded token/fusion structs、第二种 concrete modality adapter、MoT 与 offline generator head；
- viewport 多分辨率 cache、长期索引或数据库；
- late state revision；
- authenticated RF packet 和多租户权限。

### 24.2 明确拒绝进入首个切片

- 多 crate workspace、微服务、插件、DI container、通用 event bus；
- 单实现 trait、boxed adapter registry、factory/repository/manager；
- 任意 rank RF tensor、future Radar/UWB 空 variant、公共 token schema；
- public `WorldModel`/通用 modality/codec trait、packer/adapter registry、多个 temporal core/backend、万能 shared latent；
- 把 foundation Transformer 当首个 CPU candidate、部署端全主干 fine-tune、CAPC/DATTA/BVP/SHAP 框架；
- 直接依赖 H3/Cosmos/Qwen/BAGEL/Emu/Gemma/ImageBind/Mamba/V-JEPA 工程栈或权重、托管 Context-IR 补全事实、预训练或部署模型直接写 `WorldSnapshot`；
- 公共统一 packed token/vocabulary、learned hardware router、live diffusion/generator/action head、用 synthetic observation 覆盖事实；
- Track/Pose/Vitals/Gaussian/digital twin/active sensing；
- GPU runtime Cargo feature、多套 ML backend、生产权重 test-time mutation、自动模型晋升、远程训练控制面、Home Assistant/Matter；
- 为尚不存在的 session/config/neural-artifact 第二版本预写迁移器。

升级的唯一理由是出现本文档现有结构无法满足的真实数据、性能测量或外部消费者合同，不是“以后可能需要”。
