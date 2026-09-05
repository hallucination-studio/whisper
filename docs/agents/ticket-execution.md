# Ticket work 与 review 执行规则

这些规则适用于 RF 世界模型新 issue 图；每张 ticket 是一个可独立验证的切片。GitHub 原生 blocker 全部关闭且交付物可用后才可领取。旧票直接以 not_planned 关闭，新票不继承旧依赖或完成状态。

## 创建时冻结代理配置

每票创建时必须包含四项：Work、Review–Standards、Review–Spec 和 Product RF/algorithm scope。算法范围引用冻结方案的MLP/TCN/路径/CRF/T_phys等模块；非感知票必须写N/A，不能编造RF关联或另选总体模型。前三项分别写完整模型ID和reasoning，禁止留“按需选择”、继承当前会话配置或仅写模型昵称。

| 工作性质 | Work默认选择 | Standards review | Spec review |
| --- | --- | --- | --- |
| 范围明确的机械删除、脚本或文档小改 | `gpt-5.6-sol` / `low` | `gpt-5.6-sol` / `low` | `gpt-5.6-sol` / `medium` |
| 验收明确的普通功能、适配、UI及测试 | `gpt-5.6-luna` / `max` | `gpt-5.6-sol` / `low` | `gpt-5.6-sol` / `medium` |
| 跨入口集成、手机/Host组合、性能调度 | `gpt-5.6-sol` / `medium` | `gpt-5.6-sol` / `medium` | `gpt-5.6-sol` / `high` |
| 事务恢复、RF物理资格、联合递推或评测有效性 | `gpt-5.6-sol` / `high` | `gpt-5.6-sol` / `medium` | `gpt-5.6-sol` / `high` |

具体票中的配置优先于默认表。高风险行为由Spec review的Sol high覆盖；Standards review按Rust与项目规范审查范围采用Sol medium，不将风格检查等同于第二次算法审查。验收明确的普通功能默认使用Luna max；Sol low承担机械工作和普通规范审查，Sol medium承担集成及普通目标审查，Sol high用于明确高风险工作。不得把所有票统一升级为高成本配置；不使用Astra或隐式max/ultra。表中是调度决策，不声称模型能力排名由实验认证。

Work完成后，两个review分别启动独立subagent；可复用模型，但不能复用实现者上下文作为自己的独立审查。review不能启动前自动覆盖Work设定，也不能以主代理总结代替两个审查者读diff、规格和测试。

配置只约束work/review阶段，不要求规划使用同一模型。若切片超出预算或风险已改变，先缩小/拆票；确需更改时先更新ticket的明确配置与理由，再启动下一次工作，禁止运行中悄悄换模型。未声明的新组合不能自动fallback。

## Work与review的边界

Work读取票、父规格、适用AGENTS及实现，先固定验收和删除范围，再完成一个可验证路径。硬重构不保留旧schema迁移、旧API兼容、双写或功能旗标后门。每票写明删除什么、保留哪项设备输入合同；旧数据库拒绝打开，不自动擦除。

Review–Standards检查Rust/项目惯例、资源与错误边界、删除后的调用完整性和检查结果。Review–Spec检查票的行为、完整路径、反例、RF能力、无数据捷径及未越权宣称效果。高风险票两者都必须看到实际事务/递推/输入证据；普通票不扩大成全仓无限审查。

Rust代码按适用AGENTS执行fmt/check、行为测试；实质代码另跑Clippy，公开API/文档跑rustdoc；跨crate/配置/CI改变跑全workspace。手机、Python和浏览器改变执行对应构建及行为检查。无真实硬件的fixture不能关闭物理效果票；设备缺失不阻断可用fixture实现票。

每票关闭需要：范围完整、适用检查通过、两个独立review问题关闭、证据与限制清楚；代码合入不是硬件/准确率验收的替代。父规格在所有必需切片和真实验收完成前保持open。

## 领取与复核

领取时记录base SHA，验证已关闭blocker的代码/数据/制品确实进入当前base或可用输入；关闭但尚未合入不是可开始依据。每票必须列出删除范围、非目标、预期交付与检查，按一个新上下文能完成的规模限制Work。

两个review发现的实质问题由Work修复后，交原reviewer或相同配置的新独立reviewer复核实际新diff；实现者和主代理不能自行代替审查者关闭finding。范围扩大或反复失败时先校正切片与票内配置，不用静默升档或无限扩大审查范围。配置不可用时显式记录任务阻塞，不偷偷fallback。
