# 第一版本实现计划

- 状态：用户已批准实现；工作包 1.1、1.2 PASS，工作包 1.3 进行中
- 范围：事实内核、持久化与 replay、最小 RF World Model、查询与动态可视化
- 执行者：每个工作包委托一个 `gpt-5.6-sol`、low reasoning 的写 Executor
- 验收者：本线程；只审阅、运行检查、决定通过或退回，不直接修改实现

本轮已冻结 S3 firmware、native-frame 和实施门槛；用户已于 2026-08-26 批准实施。每轮审阅使用一个新的 `gpt-5.6-sol`、low reasoning、只读 clean-room Reviewer，并由本线程独立裁决后才能进入下一包。

## 1. 不可违反的执行约束

### 1.1 架构文档只读

`ARCHITECTURE.md` 是本轮实现的受保护合同，当前 SHA-256 为：

```text
bccd432f78b427f2a1e332a5994ccccf98f3b79908534693a7e79f88c1256b67
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

当前只延后 signed shared-image manifest/release key、production secure-boot/flash-encryption/eFuse/signed-OTA/provisioning ceremony、callback/encoder latency metrics/runtime histograms/p99，以及 soak/capacity/release performance gates。session persistence/recovery/faithful replay、timeline、完整 Welford/EW baseline、多设备、SignalView、完整 API/WebSocket/UI 和 estimator evidence 合同仍按本计划实施。

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
- 初始依赖上限为：序列化/TOML、一个 CBOR 实现、SHA-256、AES-256-GCM、CRC-32C、错误派生和受支持目标上的 mimalloc；运行时阶段再加入 Tokio/结构化日志，HTTP 阶段再加入一个 server stack。超出必须先由验收线程批准。
- CBOR、digest、AEAD 与 CRC-32C 不自行发明通用库；wire fixture 在 1.2 先由 Rust 冻结，1.3 的 firmware 只消费它们并做 parity，不允许反向修改。
- 前端使用原生 HTML/CSS/JavaScript 与 Canvas/SVG；不引入 Node 构建链和组件框架。

## 2. Executor/Reviewer 与本线程验收协议

每个工作包使用恰好一个新的 `gpt-5.6-sol`、low reasoning 写 Executor。每轮 review 使用一个新的同模型、同 reasoning、只读 clean-room Reviewer；共享工作区一次只允许一个 writer。

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
5. 委托一个新的 `gpt-5.6-sol`、low reasoning、只读 clean-room Reviewer 做对抗审阅；
6. 判定 `PASS` 或列出 blocker，交回原执行 agent 修复；
7. 只有当前 gate 通过后才下发下一工作包。

本线程不直接修代码。若某项需要修改架构或扩大范围，停止执行并请求用户决定。

## 3. 阶段一：事实内核

目标：配置能够描述多个 ESP32/link/profile，自有 native-frame bytes 能严格解码为保留原生坐标的 `CsiObservation`；固件与 host wire 均不兼容 ADR-018/RuView。

### 工作包 1.1：package 与 domain

所有权：

```text
Cargo.toml
Cargo.lock
src/lib.rs
src/domain/**
tests/domain_*.rs
```

实现：

- 建立单 package、edition 2024、`rust-version = "1.91"` 和 workspace lint 等价的 package lint；受支持目标的 application binary 使用 mimalloc；
- 实现身份 newtype、`DeviceId`/`KeyEpoch`/non-zero `BootGeneration`/`DeviceEpoch`、`SessionTime`/interval/time quality；
- 实现 `CsiPath`、`CsiSampleAxis`、`CsiLayout`、`IqSample`、`CsiCapture::try_new`；
- 实现 `CaptureProfile`、canonical descriptor digest、`ProfileCatalog::intern`；
- 定义 native-frame 配置随后所需的 `HeaderRoute` 和 `DecodedRoute` domain value：前者只能容纳 peer/device/key epoch 与 admission limit，后者只能在认证 body 提供 source MAC/radio facts 后解析；本工作包不接入配置文件或 socket；
- 定义 session/estimator 后续确实需要的稳定 domain/world value：`Knowledge`、baseline command/snapshot、world/evidence 使用的 ID 与 transport-neutral envelope；这里只定义不变量和构造校验，不实现 estimator 行为或 future modality 空 variant。

必测：

- 空 path/axis、坐标重复、长度不符、checked multiplication overflow；
- 同 ID descriptor 冲突；
- `HeaderRoute` 不携带 link/source MAC/radio facts，且不同 identity newtype 不能混传；
- 相同 `String` 不能跨不同 ID 类型混传；
- 内存构造 Intel `TxRx 3 × 3 × 30`，共 270 个不同 native coordinate，可通过 domain 构造；
- canonical profile fixture bytes 与 SHA-256 固定。

禁止：

- Intel decoder、adapter trait、任意 rank tensor、dataset ID 路由；
- 配置文件、CLI、Tokio、HTTP、session I/O、baseline；
- 为 future neural model 暴露 latent/token 类型。

### 工作包 1.2：固定 native-frame wire 与唯一 decoder

前置：工作包 1.1 PASS。

所有权：

```text
src/capture.rs
src/config.rs
src/wire.rs
src/esp32.rs               删除
src/domain/csi.rs          原子迁移 observation identity/sequence
src/domain/tests/csi.rs    对应 domain 回归测试
src/lib.rs                 删除 esp32 声明、加入 wire 声明
src/main.rs                替换旧 check-config 接入
Cargo.toml                 只增加 AES-256-GCM 所需依赖
Cargo.lock                 只接受上述依赖的机械更新
tests/config_validation.rs 替换 ADR 配置断言
tests/wire_*.rs
tests/fixtures/config/**   替换 ADR 配置/摘要 fixture
tests/fixtures/esp32/**    删除 ADR fixture
tests/fixtures/native-frame/**
```

实现：

- `CapturedPacket` 只保存 session/record/time/peer/wire/bytes，不打开 socket；
- 将 `CsiObservation` 的旧 `device_sequence:u32` 原子替换为经认证的 `device_epoch:DeviceEpoch` 和 `capture_sequence:u64`；不得从旧 ADR 字段、序号回退或超时猜测 epoch；
- 固件 image 与 runtime datagram 分开验收；host 只信任 manifest 中的 `wire_schema_version`/`build_digest`，不加载或复用 RuView image/parser；
- 原子移除 `src/esp32.rs` 的 ADR-018/ADR-110 magic dispatcher、`RawAdr018`/`Adr018Capabilities`、旧 `WireFormat::Esp32Udp` routing 和所有 ADR config/fixture/test；不得保留 compatibility config、parser 或 feature；
- 在同一工作包以 native-frame 的 exact peer/device/key-epoch `HeaderRoute`、source-MAC/channel policy `DecodedRoute` 替换旧 ESP32 配置及 `check-config`；配置只保存 secret root path，永不保存 AES key；
- 实现自有 native-frame 唯一 dispatcher；协议由 endpoint + version/kind 区分，不建立 magic registry；
- 实现固定 32-byte header、AES-256-GCM AAD/nonce、exact-length/tag 校验和 ESP32-S3 cleartext body grammar；`key_epoch` 非零，radio 仅接受 NonHt/Ht、20/40 MHz、`secondary=0/Above/Below` 与 LLTF/HTLTF/STBC-HTLTF，`raw_csi_bytes <= 612`、plaintext `<= 705`；V1 只保留 S3 明确给出的 `first_word_invalid`/trailing alignment，不发明 whole-frame flag 或 sample bitset；wire 接收 app 已取得的 key，不拥有 socket、secret-store 或 live replay state；
- v1 没有 wire CRC、分片、TLV extension 或 `sample_rate_hz`；只允许一个完整 datagram；
- 显式完成 ESP-IDF raw `(imaginary,real)` byte pair 到领域 `IqSample { i: real, q: imaginary }` 的映射；没有 scale wire field 或 float；
- `first_word_invalid` 和 trailing alignment 原样映射，不能按值猜 invalid，也不能补零；
- `CapabilitiesV1` 固定 descriptor/digest 与 `CsiDataV1` 绑定；只有已接受、已记录的 capability 才能构造 profile，ESP v1 只映射 `RawPathOrdinal(0)` 与 `OpaqueSampleOrdinal`；
- ESP32-S3 v1 `phase_state` 固定为 `Raw`；`DeviceEpoch { device_id, boot_generation }`、`capture_seq`、driver tick 和 receipt 进入 timeline；
- app 的 header route 只在 AEAD 前选择 peer/device/key/budget，并在认证后建立 `SensorId`；decoder 只在 AEAD 后按 source MAC/channel/PHY/LTF 做 decoded route，解析到 `RadioLinkId` 和 `CaptureProfileId`；未知 version/kind、bad tag、capability、body grammar 与两阶段 route error 保持分类不同。

必测：

- 多个非等长 S3 native-frame fixtures（明确包含 612 以下且非 128 的数量）；这些只是 fixture，不是领域常量；
- 每个合法 datagram 的所有截断前缀都返回错误且不 panic；
- Rust-only golden datagram 向量，包括 header AAD、nonce、ciphertext/tag、capability digest、every enum/bit and exact body bytes；这些 fixture 在 1.2 PASS 后冻结，firmware 不得为迁就自身输出修改它们；
- zero `boot_generation`/`message_seq`、零 count、超限、溢出、tag/length 不符、reserved bits、unknown enum、block offset、first-word/trailing bytes；
- unknown version、authenticated unknown kind、unsupported capability 与 malformed body 分类不同；
- different peer with same device_id, boot-generation transition, unprovisioned transmitter, source-MAC and channel/PHY mismatch；
- first-word/trailing accounting、phase/encoding/order/capability mismatch 时拒绝；
- 同 count、不同 native-frame descriptor 得到不同 profile ID。

### 工作包 1.3：自有 ESP-IDF firmware image

前置：工作包 1.2 PASS。固定 profile 为 `esp32s3`、ESP32-S3-DevKitC-1-compatible、display-less 8 MB QSPI flash、无 PSRAM dependency，且唯一 build toolchain 是 `espressif/idf@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb`（ESP-IDF v5.4）；host flasher 固定 `esptool==5.3.1`。在任何 `write_flash` 前，`python -m esptool --chip esp32s3 --port <port> chip-id` 和 `flash-id` 必须记录 ESP32-S3/8 MB；当前 CP2102N port 还未通过该 probe，故真实 build/flash/board gate 仍阻塞。首版不接受第二个 target、4 MB fallback、display profile 或 target abstraction。

所有权：

```text
firmware/esp32-native-frame/**
tests/fixtures/native-frame/**       只消费 1.2 已冻结的 golden vector；不得改写它们
```

实现：

- 建立一个新的标准 ESP-IDF `main` component；不引入 RuView source、parser、OTA packet 或 compatibility layer；
- 建立自有 `sdkconfig.defaults`、固定 `0x10000` partition-table offset 与 8 MB `partitions.csv`，保留 `nvs`、`otadata`、`phy_init` 的 `encrypted` flags 和两个 3 MiB OTA app slots；development flash encryption 关闭时这些 flags 不生效且不提供 at-rest security。Docker 只用固定 image digest 执行 `idf.py set-target esp32s3 && idf.py build`，不依赖 host ESP-IDF，也不复制 RuView 的 defaults/partition/release binary；
- 使用 ESP-IDF Wi-Fi CSI callback、`esp_timer`、NVS 和 mbedTLS AES-256-GCM；不添加自定义 crypto、scheduler 或 update transport；
- station 只关联 provisioned 2.4 GHz BSSID，`WIFI_PS_NONE`、无 promiscuous/channel hop/BLE coexistence；collector 的标准 UDP probe 只触发接收，不产生第二种 payload parser。CSI config 固定为三种 S3 LTF enabled、无 LTF merge/channel filter/manual scale/ACK dump；只接受 provisioned BSSID 到本机 station MAC 的 callback；
- callback 在 pointer/`len <= 612`/source/config validation 后先分配 `capture_seq`/callback tick，再非阻塞取得预分配 slot、复制完整 metadata/raw bytes、enqueue；无 slot/queue 满时丢整帧并累计 Health counter，使 source gap 可见；
- 唯一 encoder/sender task 独占 `message_seq`、sealing、UDP send 和按 v1 grammar 生成的 `CapabilitiesV1`、`CsiDataV1`、`HealthV1`；其它任务只投递 slot/counter/period signal。按配置周期重发 capability/health，保持 ESP-IDF `[imaginary, real]` raw bytes，一个 capture 只发送一个完整 authenticated datagram；
- 当前使用 unsigned development image 和 disposable test `provision.bin`；其中只含非生产 device/key、station/BSSID、probe port、collector 和 capability facts，不声明 production at-rest security。启动时校验唯一 descriptor、持久递增并 reread `boot_generation`，关联并绑定 probe socket 后才可发 capability，失败或超 budget 时 fail closed；
- build/capability digest 与 host pin 保留；signed shared-image manifest/release key、Secure Boot v2、flash-encryption、eFuse、signed OTA 和 production provisioning/release/factory ceremony 延后。runtime CSI endpoint 不承担更新职责。

必测：

- `idf.py build` 使用该唯一 target/board/IDF revision 成功，build/capability digest、wire 与 partition facts 与 build 输出一致；
- `esptool` 先通过 `chip-id`/`flash-id` 确认 target/flash，再按 build-generated flash arguments `write_flash` 并在相同 ranges `verify_flash`；拒绝未探测 port、非 S3、非 8 MB 或任何 RuView artifact；
- firmware 对 1.2 冻结的 test key/fixture 生成与 Rust 完全相同的 header、AAD、nonce、ciphertext/tag、descriptor digest 和 CSI body bytes；C/firmware/Rust parity 在此阶段验收；
- NVS boot-generation commit/re-read、zero/wrap、无 key、oversize profile、callback slot exhaustion、queue saturation 和 send failure 均不产生 partial/reused-nonce datagram，并使相应 Health counter 单调增加；
- callback 运行时不分配、锁阻塞、crypto 或 socket I/O；验证 S3 `secondary=Above/Below` 编码、first-word/trailing invalid accounting、三 LTF driver order 和 612-byte maximum；真实 bootstrap board 的最大合法 frame 同时满足 slot 与 UDP budget，correctness/drop counters 可观察。若当前 `HealthV1` schema 保留 callback/encoder latency 字段，开发固件发送 `0`；latency metrics、histogram、p99 与 soak record 延后。

### 阶段一 Gate

必须通过架构测试 1—4、6、13—16、33 的 domain 部分、工作包 1.3 的 build/vector/board checks，以及：

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
Cargo.toml                 只增加当前 session container 所需 CRC-32C/编码依赖
Cargo.lock                 只接受上述依赖的机械更新
tests/session_*.rs
tests/fixtures/session/**
```

实现：

- file header、named-field CBOR manifest 和 length+CRC-32C record；
- `SessionRecord` 的 packet、baseline command、timeline advance、closed；
- 严格 `record_seq`、monotonic `at`、schema、长度上限和 trailing data 校验；
- writer append/flush/sync 与 `durable_through_record_seq`；
- reader roundtrip、中段 CRC-32C 失败、截断尾部 recovery-seal；
- `Closed`、rotation/recovery 所需的 record-boundary primitive；
- 最小 retention 只删除最旧的 closed/recovery-sealed session，永不删除 active session，不建数据库/refcount/artifact GC；
- 使用标准库 advisory file lock；不建 sentinel、refcount database 或通用 object store；
- manifest 不含 candidate/shadow/artifact 字段；第一版本不实现 artifact 导入、选择或 GC。

必测：

- header/manifest/record 固定 bytes fixture；
- config/build/decoder/conditioning/algorithm pin roundtrip；
- 长度超限在分配前失败；
- CRC-32C 中段损坏带 offset 失败；
- 任意尾部截断只恢复完整前缀并标记 read-only；
- record sequence 重复、跳号、倒退时间和 Closed 后 append 被拒绝；
- sync/append 故障不产生可发布状态。

### 工作包 2.2：capture/replay 应用壳

前置：工作包 2.1 PASS。

所有权：

```text
src/app.rs
src/secrets.rs
src/main.rs
src/lib.rs                 仅增加模块声明/最小启动 API
Cargo.toml                 只增加已批准的 Tokio/结构化日志依赖；secret loader 不加依赖
Cargo.lock                 只接受上述依赖的机械更新
tests/app_capture_*.rs
tests/app_replay_*.rs
```

实现：

- `capture | replay | check-config` CLI；
- app 独占 socket、文件、任务和 shutdown，领域模块不读取系统状态；
- 实现具体 app-owned local secret loader：从配置指向的受控 `secret_root/<device_id>/<key_epoch>.key`（canonical unsigned decimal directory names）读取恰好 32 bytes；缺失、非 32 bytes 或 I/O error 分类拒绝。它不是 trait/provider、TOML field、session record、环境变量 fallback 或 legacy-key parser；测试使用独立 temporary secret root；
- UDP receive buffer 使用 65,535 bytes，完整接收后再按业务上限拒绝；
- ingest 总序为 size/fixed header parse/`HeaderRoute(peer,device,key epoch)`/key lookup/per-route budget → AEAD → bounded replay admission → assign record/time → session append → cleartext decode/`DecodedRoute(source MAC,channel,PHY,LTF)` resolve；
- replay checkpoint 只保存有界的非秘密 window state；provisioning 创建已 sync 的空 checkpoint，启动先用 active session 已落盘 header 重建，再绑定 socket；rotation/shutdown 在 `Closed` sync 后原子更新，任何缺失/损坏都 fail closed；
- 只有完整 data-plane admission 成功的 encrypted datagram 才会 durable；认证后的 unknown kind、unsupported capability 或 malformed cleartext 才记录分类 reject 并继续；
- replay 使用 manifest pin 和同一个 native-frame decoder；第一版本此时输出 typed decode/health 流，阶段三接入相同 Engine 后升级为 semantic replay；
- graceful shutdown 写 `Closed` 并 sync；不建 HTTP、actor graph 或 writer task 拆分。

必测：

- 超大 UDP datagram 被完整接收后明确拒绝，不伪装成截断包；
- unknown peer/version/key、bad tag、replay 和 admission rate/byte budget 不创建 `CapturedPacket`，只更新有界 health；
- missing/malformed secret file 与不同 `(device_id,key_epoch)` key lookup 均分类拒绝，key bytes 不出现在 config/session/error；
- message sequence duplicate/old/new boot generation 和 controlled reordering 按固定 replay window 验证；
- host restart 和 session rotation 后重放同一有效 datagram 被拒绝；checkpoint 缺失/损坏 fail closed，fresh key epoch provisioning 建立已 sync 的空 checkpoint；
- append 失败后 decoder/状态更新未发生；
- raw packet live/replay 解码结果相同；
- authenticated malformed body、unknown kind、capability unavailable 与 source-MAC mismatch 的 raw packet 已记录但不进入推理输入；
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

实现以 `DeviceEpoch` 为 source 的 `capture_seq`、profile partition、gap/duplicate/reorder、active watermark、固定非重叠窗口、missing span 和 `TimelineAdvance`。不实现 wrap 或由序号猜测 epoch change；所有时间由参数传入，不读取墙钟。

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
- `CoordinateEvidence` 和 `LinkStepEvidence` 作为 estimator 的可审计输出；第一版本不构造 candidate input。

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
- sequence/gap/device-epoch boundary/rate/jitter/baseline command timeline；
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

- 架构摘要仍为 `bccd432f78b427f2a1e332a5994ccccf98f3b79908534693a7e79f88c1256b67`；
- 架构测试 1—34 有逐项对应的 runnable test 或明确端到端验收；
- 没有 `unsafe`、未授权依赖、future feature flag、空 trait 或第二套 parser；
- domain/session/API/UI 没有权威固定 RF shape；
- 没有 `candidate.rs`、ML runtime、数据库或第二事实源；
- `cargo tree` 中没有未授权的 GPU/ML/frontend/database 依赖。

### 7.2 端到端验收场景

使用至少两个 authenticated ESP32 route 和两个不同 profile/长度的真实 captured datagram fixtures/corpus，在同一 window 内并发输入；另用当前可用真实开发板完成 authenticated live smoke：

1. capture 写入 closed session；
2. live 产生多个独立 stream/link belief 和单一 world snapshot sequence；
3. baseline 明确 BeginLearning/Commit 后才从 Unknown 进入 Active；
4. gap/device-epoch boundary/profile change 不污染另一 stream；
5. replay 产生相同 typed semantic snapshots；
6. HTTP 能查询 topology、signals、timeline、world、evidence 和 baseline；
7. WebSocket 只通知小 envelope，丢 delta 后可重新 GET；
8. UI 同时显示不同 native coordinate 数和 missing spans；
9. 只有已认证且通过 admission 的 datagram 保留 raw bytes；unknown kind、malformed body 和 capability/source mismatch 不进入 world model，unknown peer/version/key、bad tag、replay 和 oversized/budget traffic 只进入有界 health；
10. shutdown 后 session 可独立检查和 replay。

### 7.3 第一版本完成的含义

完成后可以声明：

- 至少两个 authenticated ESP32 route 的真实 captured datagram corpus 已证明同窗 ingestion、独立 stream/link/baseline 和单一 world snapshot sequence；当前可用真实开发板已通过 authenticated live smoke；
- raw session 可检查、恢复和 faithful replay；
- 系统能输出可解释的 `Stable | Changing | Unknown(reason)`；
- UI 不依赖固定 tensor，能够并列显示不同 native layout。

不能声明：

- 已完成 30 分钟 `2×` 负载发布门禁；
- 已完成多台物理 ESP32 的长期 soak；
- 已实现 CPU 自监督演化或 RF 预训练/部署神经模型；
- 已支持 Intel 5300 实采或相干 mixed-device fusion；
- 已实现 presence、姿态、动作、生命体征或跨环境语义泛化。

第一版本验收通过后，是否进入多物理板长期 soak/performance 或 CPU AR(1) 由用户另行决定，不自动继续。
