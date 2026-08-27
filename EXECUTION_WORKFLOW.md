# Agent Execution Workflow

本文件只规定 agent 如何执行、审阅和修复代码。具体功能、工作包顺序、文件所有权和验收条件始终以 `IMPLEMENTATION_PLAN.md` 与 `ARCHITECTURE.md` 为准。

## 1. 目标

- 新 agent 不继承历史对话，避免结论、解释和失败路径污染上下文。
- 严格按当前工作包执行；超出计划的实现即使测试通过也必须拒绝。
- 同一时间只允许一个 agent 写代码；并行只用于互不重叠的只读审阅。
- 用短检查点、focused checks 和一次统一全量验证减少无效等待与重复编译。
- 所有实现和修复遵循 Ponytail full：最小、直接、无预留扩张。

## 2. 权威与角色

权威顺序：

1. 用户当前指令。
2. `IMPLEMENTATION_PLAN.md`。
3. `ARCHITECTURE.md`。
4. `AGENTS.md` 及其指向的适用指南。
5. 附近代码、测试和既有约定。

角色固定：

- **主线程**：冻结基线、下发任务、运行机械检查和全量验证、裁决 findings、决定 `PASS` 或退回。主线程不修改实现代码。
- **Executor**：当前工作包唯一 writer。只实现获准范围和最小测试。
- **Reviewer**：每轮新建的只读 clean-room agent。独立检查当前仓库快照，不修改文件。

Reviewer 不是 fixer，Executor 不能自审通过。

## 3. 上下文隔离

所有新 Executor 和 Reviewer 都使用：

```text
fork_turns: none
```

空上下文不是空材料：agent 必须读取仓库中的权威原文和当前代码，但不得继承其他 agent 的解释或结论。

### Executor 输入

Executor 只接收执行任务包。它按计划要求完整读取 `IMPLEMENTATION_PLAN.md`、`ARCHITECTURE.md` 和适用的仓库指南。同一工作包的后续修复继续使用原 Executor，避免重复加载完整文档。

### Reviewer 输入

Reviewer 只接收审阅任务包，并自行读取当前 diff、计划原文、相关架构章节、测试和调用链。不得向 Reviewer 提供：

- Executor 的行为摘要、设计解释或自评；
- 主线程对实现正确性的判断；
- 上一轮 Reviewer 的 findings；
- “应该找到什么问题”的提示。

主线程运行的原始检查结果可以提供，因为它们是可复现证据，不是实现结论。

每轮复审必须创建新的 Reviewer；不得复用已经看过旧实现或旧 findings 的 Reviewer。

## 4. 标准流程

### 4.1 冻结基线

主线程在下发工作包前记录：

- `git status --short`；
- 当前工作包允许修改的文件；
- `ARCHITECTURE.md` 和 `IMPLEMENTATION_PLAN.md` 的 SHA-256；
- 当前第一个可复现失败；
- 工作包要求的检查命令。

工作区可以是 dirty 的。任何既有改动都必须保留，不得回滚、覆盖或重新解释为本工作包产物。

### 4.2 下发 Executor

每个工作包只创建一个新的 Executor。共享工作区内不得同时存在第二个 writer。

Executor 必须先确认：

- 工作包和允许文件；
- 受保护文档哈希；
- 禁止项；
- 准备处理的第一个最小行为闭环。

发现计划矛盾、缺口或必须扩大范围时立即停止，只报告证据和最小选项，不修改计划或架构。

### 4.3 微批次实现

Executor 按依赖顺序一次闭合一个最小行为：

```text
root cause -> minimum code -> one focused regression check -> next behavior
```

不要先做宽重构再统一编译。结构或 API 变化后应立即运行 focused `cargo check`；行为变化后立即运行对应测试。全量验证留给主线程的机械 Gate。

### 4.4 短检查点

Executor 每 2 至 3 分钟提供一次短检查点：

```text
changed: <files or none>
check: <last command and result>
blocker: <first concrete blocker or none>
next: <one bounded action>
```

持续运行且有输出的编译或测试算有效进展。连续两个检查点没有产物、没有新的错误证据且没有明确阻塞时，主线程中断 Executor，把任务缩小到当前第一个失败后再继续。禁止无限被动等待。

### 4.5 机械 Gate

Executor 停止写入后，主线程先检查：

1. 两份受保护文档哈希未变化；
2. changed files 是工作包允许集合的子集；
3. 没有无关重构、兼容层、预留代码或测试弱化；
4. 依赖、feature 和 public API 变化均由工作包明确要求；
5. focused checks 已通过；
6. 工作包要求和当前全部回归通过。

机械 Gate 未通过时不启动 Reviewer，直接把第一个确定失败退回 Executor。

仓库没有更具体命令时，主线程统一运行：

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo doc --locked --workspace --all-features --no-deps
```

Reviewer 不重复运行这组全量命令。需要证明 finding 时，只运行最小复现或 focused check。

### 4.6 Clean-room Review

机械 Gate 通过后才创建 Reviewer。

- 普通工作包：一个 Reviewer 同时检查正确性、计划范围、测试和 Ponytail。
- 安全、wire、持久化或跨合同高风险工作包：可并行使用两个 Reviewer，一个检查正确性与信任边界，另一个检查计划范围、API、依赖、测试和 Ponytail。
- 并行 Reviewer 必须只读且职责不重叠，避免重复审阅和 Cargo 资源争用。

Reviewer 只能返回：

- `PASS`；
- `BLOCKER`，附权威条款、代码位置和可复现证据；
- `INSUFFICIENT_EVIDENCE`，说明缺少的具体证据。

不得把偏好、未来增强或 plan 外建议列为 blocker。

### 4.7 裁决与修复

主线程逐条裁决 Reviewer findings：

- 有权威条款和证据的当前工作包缺陷：接受；
- 重复 finding：合并；
- 无证据、纯偏好、未来工作或超出计划：拒绝；
- 需要修改计划或架构：停止并请求用户决定。

主线程只把已接受 blocker 的最小证据包交回原 Executor。Executor 修复后重新经过机械 Gate，再由全新的 clean-room Reviewer 独立复审。

```text
Executor -> Mechanical Gate -> Fresh Review -> Adjudication
    ^                                      |
    +----------- accepted blockers --------+
```

只有机械 Gate、工作包验收和 fresh review 全部通过，主线程才判定 `PASS` 并进入下一工作包。

## 5. Ponytail Full Gate

每次实现和修复都按以下顺序判断，并停在第一个能正确解决问题的位置：

1. 该代码是否确实需要存在；
2. 仓库是否已有可复用实现；
3. 标准库是否已经解决；
4. 已安装依赖是否已经解决；
5. 最少代码如何闭合根因和一个回归测试。

硬规则：

- 不增加计划未要求的抽象、trait、factory、registry、配置项或扩展点；
- 不增加计划未批准的依赖、feature、兼容别名或 public API；
- 不为未来工作预留 scaffolding；
- 优先删除无效代码，避免并行的新旧路径；
- bug 修在所有相关调用者共享的根因位置，不给每个调用者打补丁；
- 不削弱 trust-boundary validation、安全措施、错误处理或数据完整性；
- 非平凡逻辑只增加能证明该行为的最小回归测试，不扩建测试框架；
- 实现超过当前工作包时必须拒绝，不以“顺手完成”放行。

## 6. 任务包模板

### Executor Packet

```text
mode: write, single owner
context: fork_turns none
authority: IMPLEMENTATION_PLAN.md + ARCHITECTURE.md + applicable guidelines
work package: <exact heading>
allowed files: <exact list>
accepted behavior: <exact plan clauses>
forbidden: <exact plan clauses + no extra API/dependency/abstraction>
protected hashes: <sha256 values>
first failing evidence: <command and output>
focused gate: <commands>
checkpoint: every 2-3 minutes
output: changed files, raw checks, remaining blocker; no commit
```

### Review Packet

```text
mode: read-only clean-room review
context: fork_turns none
snapshot: <baseline identifier + current changed files>
authority: repository plan and architecture source files
scope: <correctness axis or scope/Ponytail axis>
evidence: <main-thread raw validation output>
exclude: executor summary, parent conclusions, prior findings
output: PASS | BLOCKER | INSUFFICIENT_EVIDENCE
finding format: severity | authority line | code line | reproduction
```

## 7. 硬拒绝条件

出现任一情况，当前结果不得进入 Review 或判定 `PASS`：

- `ARCHITECTURE.md` 或 `IMPLEMENTATION_PLAN.md` 与基线哈希不同；
- 修改工作包允许集合以外的文件；
- 实现了计划外功能或未来工作；
- 新增未批准依赖、feature、public API、兼容路径或预留抽象；
- 删除、跳过或弱化有意义的测试来获得绿色结果；
- 只报告“agent 仍在运行”而没有可验证产物或错误证据；
- Reviewer 继承历史上下文或收到上一轮结论；
- 必需检查未运行、失败或结果来源不明；
- agent 修改、提交或改写 Git 历史。
