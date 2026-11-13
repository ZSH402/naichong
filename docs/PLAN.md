# 项目计划表

> 本文件是跨轮次的记忆锚点。每完成一个阶段，更新「进度」一节。
> 最后更新：阶段 A 开始前

## 1. 项目目标

以 **DSH 为主控**，构建轻量级异构安全测试 Agent 编排系统。核心诉求：

- 一个主控（DSH）、多个专业执行单元、统一任务契约、证据闭环、代码强制约束
- 副 agent **热插拔**
- 判断、决策、领导力（DSH 原生缺失的部分）

**关键定位修正（已确认）**：不是"拼三个 agent 的代码"。DSH 上游已经提供异构副 agent 的全部基础能力，项目重心是**在其上写安全测试领域层**。

## 2. 已完成（附证据位置）

| # | 交付 | 状态 | 证据 |
|---|---|---|---|
| 1 | DSH 能力核查（§11 六条待验证事项） | 完成 | `DSH能力核查.md` |
| 2 | 强项搬迁判定（CC / OpenClaw） | 完成 | `强项搬迁清单.md` |
| 3 | 项目实施方案 + 核实结果 | 完成 | `项目实施方案.md` |
| 4 | 决策层设计（pre-step 落点、三处缺口） | 完成 | `决策层设计.md` |
| 5 | `dsh-secops` 插件（范围闸 / 预算闸 / 停止条件） | 完成 | `dsh-secops/` |
| 6 | 端到端验证（真实会话，越界拒绝 + 授权放行） | 完成 | `端到端验证报告.md` |
| 7 | 破甲与验收环境拆分 | 完成 | `破甲与验证环境.md` |
| 8 | dsh-purge 0.2.x 适配（38/44 有效） | 完成 | `purge-compat/` |
| 9 | dsh-secops 0.2.2 兼容性验证 | 完成 | `dsh-secops/COMPAT-0.2.2.md` |
| 10 | HITL 层（风险分级 + 硬底线 + 审批） | 完成 | `dsh-secops/src/hitl.ts`、`test/hitl.mjs` |
| 11 | 方向级 agent 调度（注册表 + 失败降级 + verdict 解析） | 完成 | `dsh-secops/src/agent-registry.ts`、`agent-dispatch.ts`、`test/agent-dispatch.mjs` |
| 12 | 真实 agent 接入（5 方向，端到端实测） | 完成 | `dsh-secops/src/agent-registry.ts`、`test/agent-e2e.mjs` |
| 13 | 挂进项目 runtime 并真机验证 | 完成 | `/root/proj/home/profiles/headless/cordis.patch.yml`、`dsh-secops/sync-to-runtime.sh` |

## 3. 关键事实（不要重复推导）

### 3.1 DSH 上游已有，不用重做

| 能力 | 提供者 |
|---|---|
| 副 agent 热插拔 | `subagent-*` 8 个后端，bundle 开关，活 agent 下次请求生效 |
| Claude Code / Codex / ACP 作副 agent | `subagent-claude-code` / `-codex` / `-acp`（**rc 包中缺失，需 master**） |
| 任务板 / 归属 / 依赖 | `agent-team` + `tool-agent-team`（仅子 agent 树内，不跨进程） |
| CC hooks 协议 | `dsh-hook-protocol`（完整线协议）+ `hooks-claude-code` |
| 工具策略拦截 | `ctx.tools.guard()`（单调拒绝）+ `restrict({allow,deny})` |
| 决策阶段挂载点 | `agent/pre-step` waterfall（`reject` → turn blocked） |
| Token 计量 | `ctx.tokenMeter`（replay-aware，只测量不拦截） |
| 会话/投影 | `ctx.sessionProjections`（fold 式，随 session log 持久化） |

### 3.2 DSH 明确没有（= 自研范围）

| 缺口 | 说明 |
|---|---|
| 网络出站强制 | `ctx.sandbox` 只管文件；`dsh-http-proxy` 是跟随不是拒绝 |
| 预算 enforcement | `tokenMeter` 只测量；`QUOTA` 只是识别 provider 错误措辞的正则 |
| 持久任务队列 / 调度器 | `jobs` process-local、`workflow` 前台阻塞、`schedule` 最小 300s 且只是提醒 |
| 知识点级 provenance | session log 是会话级，接不住「事实/假设/推断/证伪」四分类 |

### 3.3 架构约束

- **不存在需要打补丁的特权内核**。扩展方式是挂插件，不是改核心（`docs/architecture.zh.md` 原文）
- 定制形态：profile + 组合包 + `cordis.patch.yml` + `--patch` overlay
- 插件顺序由 `inject` 服务依赖决定，**不由文件顺序决定**
- cordis 的 `prepend` 是 `unshift`，**后注册者更靠前** → 安全拦截必须走 `guard`，不能放 `pre-step`

### 3.4 0.2.2 的关键变化（已核实）

- `dsh-tools` 拆包：`registry / pipeline / executor / batch / contracts`
- 引入可插拔 `ToolExecutor`，但 **`checkGuards` 仍在 core pipeline**（`pipeline.js:402`），换 executor 绕不过 guard
- `ToolGuard` / `guard()` / `PreStepDecision` 签名未变
- `agent/pre-step` payload 多 `modelSelection`；`ToolExecutionInput` 多可选 `schema`

### 3.5 环境坑

- npm registry 被指向 `registry.npmmirror.com`，装新版本会卡死 → 用 `--registry=https://registry.npmjs.org`
- 当前 `~/.dsh` 环境被 `dsh-purge` 打了 36/44 patch → **不能用于验证权限行为**（假阴性）
- TS 需 `preserveSymlinks: true`；Node ESM **不**遵循它
- `dsh-tools` 用 `@deepseek-ai/schemastery` 的 `z`，不是 `zod` 的 `z`

### 3.6 破甲与验收必须分环境

- 破甲环境：验 dsh-secops 的业务闸（与 purge 无关，已实证）
- 干净环境：验 DSH 自身限制（审批 / 沙箱）

## 4. 阶段计划

### 阶段 A：决策记录持久化（已完成 ✅）

**目标**：把 pre-step 的决策从内存 ring buffer 变成随 session log 持久化的 projection。

**内容**
- `DecisionRecord` 数据结构（候选集 / 所选 / 依据 evidence_refs / 放弃项 / 可证伪条件 / 饱和判据）
- `ctx.sessionProjections.register()` 注册投影
- 决策写入 = session 事件 append
- 拒绝路径接 `agent/pre-step`

**验收结果**
- 类型检查对 0.2.2 通过（exit 0，strict + skipLibCheck:false）✅
- 运行时 `test/decision.mjs` **10/10 passed** ✅
- 写入提交验证：`appendPluginRecord` 返回递增 seq ✅

**交付**：`dsh-secops/src/decision-record.ts`（schema + projection + 写入/读取）、`decision.ts` 接线、`test/decision.mjs`

**关键断点（重要）**：`appendPluginRecord` / `pluginRecordOf` / `PluginRecordMap` 是 **0.2.2 新增**，0.1.5 的 `dsh-session` 完全没有（实测 0 次匹配）。因此**决策记录持久化是 0.2.2 独占能力**，0.1.5 上无法编译。这确定了项目必须走 0.2.2。

**设计要点**
- `sessionProjections` 用 `ctx.get()` **可选探测**，不写进 `inject`。硬依赖会让插件在精简 profile 里 PENDING，连范围闸和预算闸都装不上
- **cordis 的 effect 作用域陷阱（重要）**：插件的 `apply` 若抛错，所有已注册 effect（包括 guard）会被整体回滚。所以任何可选服务的获取都必须 try/catch，否则会出现"插件加载失败 → 安全闸静默消失"这种最危险的失败模式
- 记录用 `plugin:` 命名空间，不污染 `SessionEventMap`
- projection 是 host-only（不进客户端快照，但照样 checkpoint）
- `rationale` 字段故意不存在，只有 `evidenceRefs` —— 没有证据引用的决策在复盘时视为无效
- 写入失败不影响 pre-step（记录是副产品），但会 `logger.warn` 留痕

### 阶段 B：跨进程调度（已完成 ✅）

**目标**：补 `agent-team` 覆盖不到的外部 worker 调度。

**实现**
- `src/queue-store.ts`：append-only JSONL 持久化（不用 session log —— 队列跨会话，session log 是会话级）
- `src/queue-runner.ts`：进程组执行器（`detached: true` + `kill(-pid)`）、超时、证据落盘
- `src/queue-tools.ts`：`worker_submit` / `worker_status` 两个模型侧工具
- 配置 `queue.enabled` 开启，随 `ctx.effect` 有序关闭

**验收结果**
- `test/queue.mjs` **13/13 passed**
- `test/queue-tools.mjs` **8/8 passed**
- 关键项：超时后**孙进程同组被杀**（`kill(-pid)` 打进程组）、崩溃后 `running` 降级 `interrupted`、同 id 幂等、并发上限生效、证据 `stdout/meta.json` 可读

**设计要点**
- 队列介质刻意不用 session log：调度状态和对话记录是两种生命周期
- `drain()` 必须同时判 running 与 queued，因为 `pump()` 走 microtask，否则会提前返回
- 证据不内联进工具返回值，只给目录路径 —— 避免大块 stdout 灌进上下文
- `output.schema` 不支持 `type:['number','null']`，单类型 + 缺省字段

### 阶段 C：provenance（已完成 ✅）

**目标**：知识点级的「已验证事实 / 待验证假设 / Agent 推断 / 已证伪路径」。

**实现**
- `src/provenance.ts`：claim schema、状态推导纯函数、plugin record 写入、projection
- `src/provenance-tools.ts`：`ClaimStore` + 四个工具（`claim_assert` / `claim_evidence` / `claim_refute` / `claim_query`）

**验收结果**
- `test/provenance.mjs` **22/22 passed**
- `test/provenance-session.mjs` **6/6 passed**（claim 写入 session log 并折叠）

**核心判据（与 OpenClaw 的根本区别）**
- OpenClaw：turn 被网络工具结果污染 → untrusted。安全测试证据全部来自网络，照搬会让一切不可信
- 本实现：**独立复现次数**。由调用方声明 `pathKey`（`http:differential` / `tool:recompute` / `role:other-user`），同 pathKey 的重复证据只算一条路径，达到 `CONFIRM_THRESHOLD=2` 才升 confirmed

**状态机**
- `hypothesis`（无证据）→ `partial`（≥1 条路径）→ `confirmed`（≥2 条独立路径）
- `refuted` 是**单向闸门**：一旦证伪，后续新证据不会把它翻回 confirmed（要翻必须显式重新 assert）
- `inference` 独立标出 Agent 推断，不与观测混淆
- `settledIds()` 供调度器跳过已定论路径 —— 对应摘要 §6.1「已证伪且无新证据不重复派发」

### 阶段 D：网络出口（已完成 ✅）

**目标**：让越界请求在内核层被拒，同时不影响 DSH 自身模型流量。

**实现**
- `src/egress.ts`：`EgressProxy`——监听 unix socket，支持 CONNECT 隧道与明文 HTTP，按 allowlist 放行，逐次回调判定（用于证据）
- `src/netns.ts`：`netnsCommand()`——bwrap `--unshare-net` 包裹，把代理 socket 绑进 netns，内建 socat 转 loopback TCP，注入代理环境变量
- `queue-runner` 集成：`netns` 选项启用后每个任务都在独立 netns 执行

**验收结果**
- `test/egress.mjs` **9/9 passed**
- `test/netns-queue.mjs` **3/3 passed**（队列任务在 netns 内，允许目标通、越界目标拒）
- 关键项：netns 断直连、代理 allow/deny、**代理关闭后 fail closed**、**宿主出站不受影响**

**实测约束（本机验证）**
- `--ro-bind / /` 下 `/run` 与 `/tmp` 都不能直接 `mkdir`，必须先 `--tmpfs <dir>` 再 `--bind <socket> <dir>/<name>`
- 选 `/run` 而非 `/tmp`：不干扰被测命令对 `/tmp` 的使用
- `NO_PROXY` 含 `127.0.0.1` 会让 curl 绕过代理直连；需要强制走代理的调用方应显式 `--noproxy ''`
- 基线 200 → `unshare -n` / `bwrap --unshare-net` 均为 000，隔离真实生效

**设计取舍**
- 没有走自定义 `SandboxProvider`：那个 seam 的 `confine()` 只表达文件效应策略，网络语义塞进去会污染契约。改为在队列执行器这一层包裹命令，职责更清楚
- 代理与 netns 是**两道**拦截，缺一不可：只做代理，worker 直接 socket() 就绕过；只做 netns，worker 完全不能工作

### 阶段 E：证据自动归档（已完成 ✅）

**目标**：队列产物自动接入 claim 体系，去掉手工 `claim_evidence` 这一环。

**实现**
- `queue-runner` 增加 `onFinish` 终态回调（done/failed/cancelled 都触发）
- `queue-tools.worker_submit` 增加 `claim_id` 参数
- `createEvidenceArchiver()` 抽出归档器，index 与测试共用同一份逻辑

**验收结果**：`test/evidence-archive.mjs` **14/14 passed**

**关键规则**
- `pathKey = task:<kind>`：同一类工具的重复执行**不算**独立路径。独立复现要求方法不同，不是同一命令跑两遍
- 只有 `done` 才附证据：失败任务说明命令没跑通，不是对断言的观测
- 未知 claim_id 在提交时即被拒，不留悬空关联

### 阶段 F：端到端验证（已完成 ✅）

见 `端到端验证-0.2.2.md`。真实 DSH 0.2.2 + 真实模型跑通三工具链路与证据自动归档闭环。

**过程中发现并修复的真实缺陷**：`claim_query` 原本不返回 evidence 明细，模型无法核实证据数量。已补 `evidenceCount` + `evidence[]`。

**发现的未解问题**（已在阶段 G 解决）：独立路径数只度量数量、不度量相关性，模型可以拿无关任务产物充当证据。

### 阶段 G：证据相关性闸（已完成 ✅）

**目标**：堵住「拿无关任务产物充当证据」。

**实现**
- `src/relevance.ts`：从断言文本确定性提取锚点（path / method / param / host / status），证据的**实际执行内容**必须触及至少一个锚点
- `ClaimStore.attach` 强制校验，失败返回带理由的结果
- `verifiedPaths` 只数 `strong` 证据；`weak`（仅产物命中，可被伪造）不计入升级口径
- `worker_status` 回传 `archived` / `rejectReason`，模型能看到拒绝原因

**验收结果**
- `test/relevance.mjs` **25/25**
- `test/provenance.mjs` **32/32**
- `test/evidence-archive.mjs` **21/21**
- 端到端：模型故意用 `observes` 自述试图绕过 → `archived: false` + 明确 rejectReason + `evidenceCount: 0`

**两次端到端发现的设计缺陷（都已修）**
1. `claim_query` 不返回 evidence 明细，模型无法核实证据数量 → 补 `evidenceCount` + `evidence[]`
2. **`observes` 自述可绕过校验** —— 模型只需在 observes 里复述断言原文即可。判据改为「实际执行内容 + 系统读取的产物」，自述彻底退出判据

## 4.5 purge 现状（更新）

- **上游 `YuJunZhiXue/dsh-purge` 已 404**，本地 1.1.21 是残血版（44 条补丁）
- **社区维护版 `kingcharleslzy-ai/dsh-purge@1.6.88`**：86 条补丁，声明适配 0.2.2-rc.1，本机实测 **67/86 应用成功**
- 详见 `purge-上游调研.md`
- **与 dsh-secops 兼容性已验证**：`dsh-tools` 未被动（guard 安全）；`dsh-agent-loop` 的改动是加固（pre-step 契约不变）

### 阶段 I：跨会话 claim 持久化（已完成 ✅）

**目标**：一次 engagement 有多轮会话，断线重开后断言与证据不能丢。

**实现**
- `ClaimStore` 增加 `storePath`（JSONL 快照，append-only，last-wins）
- 配置 `provenance.store`；不配置则保持纯内存（默认行为不变）
- 损坏行跳过（写入中途崩溃留下的半行不会阻断加载）

**验收**：`test/persistence.mjs` **14/14**，含跨会话追加证据升 confirmed、证伪状态跨会话保持、`settledIds` 跨会话可用

**为什么重要**：`settledIds()` 是「已证伪不再派发」的执行体。如果它只在单会话内有效，跨轮次测试就会重复打同一条死路。

### 阶段 J：证据可重放（已完成 ✅）

**目标**：让证据自己证明自己 —— 不接受无法复现的产物。

**实现**
- `src/replay.ts`：`replayCommand()`（独立进程组执行 + 超时）+ `skeletonDigest()`
- `skeletonDigest` 的归一化：ISO 时间/UUID/长 hex/普通数字 → 占位符；
  **HTTP 状态码按上下文保留**（`-> 200` / `status: 500` / `HTTP/1.1 200`）
- worker 归档时自动记录 `source`（taskId + argv + cwd）与 `baselineDigest`
- `claim_verify` 工具：重放所有可重放证据，回写结果，重算状态
- 三条计数口径：`independentPaths` ⊃ `verifiedPaths`(strong) ⊃ `replayPaths`(strong + 重放通过)

**验收**：`test/replay.mjs` **23/23**，全量 **186 项全绿**

**过程中修掉的两个归一化 bug（都会让重放失去判据）**
1. 一律抹掉数字 → `-> 200` 与 `-> 500` 摘要相同，重放永远"一致"
2. `\b\d+\b` 匹配不到 `12ms` 里的数字（数字与字母之间不是单词边界）

**已知局限（必须记住）**：重放能挡住「编造没跑过的结果」，挡不住「跑了但没测到东西」。
`echo "PUT /api/user 200"` 摘要稳定且含锚点，仍会被判为可重放。
这一层要靠相关性闸 + 独立路径，不能指望重放。

### 阶段 K：决策纪律（已完成 ✅）

**目标**：把"判断与决策的质量"变成可检测的模式，而不是靠模型自觉。

**只做工程上能确定的部分**：不判断"决策对不对"（那需要领域知识），只判断"决策过程是否失能"。

**三条规则（全部基于可观测的决策流）**
- `EMPTY_REASON`：reject 的理由少于 10 字符 = 没说清
- `REPEATED_REJECTION`：同一理由前缀连续 3 次 = 卡死
- `STALLED`：同一 agent 连续 5 步只拒绝不前进 = 空转

**实现**
- `src/decision-policy.ts`：`DecisionPolicy` 观测器 + `audit()` 报告
- pre-step 里每次决策都过一遍，违规写日志（含可执行 hint）
- `decision_audit` 工具：把违规模式暴露给模型和用户

**验收**：`test/decision-policy.mjs` **19/19**，全量 **205 项全绿**

**为什么把审计暴露给模型**：连续三次同样理由的拒绝，在单轮上下文里看起来正常，在审计视角下是卡死。让它看见自己的模式，比在提示词里写「不要重复」有效。

## 5. 进度

- [x] 1-9 前置工作
- [x] 阶段 A 决策记录持久化
- [x] 阶段 B 跨进程调度
- [x] 阶段 C provenance
- [x] 阶段 D 网络出口
- [x] 阶段 E 证据自动归档
- [x] 阶段 F 端到端验证（0.2.2 + 真实模型）
- [x] 阶段 G 证据相关性闸
- [x] 阶段 H purge 调研（**环境切换已回滚，不再执行**）
- [x] 阶段 I 跨会话 claim 持久化
- [x] 阶段 J 证据可重放（skeletonDigest + claim_verify）
- [x] 阶段 K 决策纪律（三条规则 + decision_audit）
- [x] 阶段 L 工程审计与加固（两级摘要 / 工具级独立路径 / 失败注入）
- [x] 阶段 M 能力吸收核对 + Model Fallback（8 项核对，1 项实现）
- [x] 阶段 N 外部能力接入（claude-code subagent + hooks 已挂载并实测）
- [x] 阶段 O HITL 审核层（硬底线 / 风险分级 / 审批接缝）
- [x] 阶段 H purge 上游调研与切换（社区版 1.6.88，67/86）


### 阶段 L：工程审计与加固（已完成 ✅）

**审计发现并修复的三个真实缺陷**

1. **重放的数字归一化过度**（严重）：`\d+ → <n>` 让 `found 5000 items` 与 `found 3 items`
   摘要相同，内容实质不同却被判为一致 —— 等于给证据造假开后门。
   修法：两级摘要。`strictDigest` 保留数字（只抹时间戳/UUID/长 hex），
   `structuralDigest` 再抹数字。比对分三档：strict（数值一致，才算复现）/
   structural（仅结构一致，记为弱一致）/ none。状态码按上下文保留，变化即判 none。

2. **独立路径只按自报 pathKey 去重**：模型换个标签用同一工具跑两次就能凑出两条路径。
   修法：`toolPaths()` 按**可执行文件**去重，confirmed 门槛改成「至少 2 个不同工具」。
   同一工具换 pathKey 不再达标（已有反例测试）。

3. **快照写入静默吞错**：磁盘满或权限问题时证据静默丢失。
   修法：`persistFailures` 计数 + `lastPersistError` 暴露，内存状态仍可用。

**新增失败注入测试** `test/failure-injection.mjs`（16 项）
覆盖：快照写失败可见、队列损坏行跳过、进程死后 running 降级、重放超时不留孤儿进程、
代理未启动时 fail closed、代理拒畸形目标、超大输出截断。

**验收**：全量 **226 项全绿**

### 阶段 M：能力吸收核对 + Model Fallback（已完成 ✅）

**YG 指定吸收的 8 项，逐项核对 DSH 0.2.2 的结果**

| 能力 | 状态 |
|---|---|
| OpenClaw Provider 体系 | `ctx.llm.registerAdapter` 已有 |
| **OpenClaw Model Fallback** | **真缺 → 本阶段实现** |
| OpenClaw Runtime/Model 解耦 | 部分（preset + agentOptions），未动 |
| Claude Code Hooks | 包在 npm 有（0.2.2-rc.1），**未装** |
| Claude Code 上下文管理 | `compaction` + `tool-result-pruner` 已有 |
| Claude Code Subagent 隔离 | `subagent-claude-code/acp/codex` 在 npm 有，**未装** |
| OpenClaw Session 状态管理 | session projection 已有 |
| Claude Code Skills 动态加载 | `dsh-skill` + `dsh-skill-filesystem` 已有 |

**结论：8 项里 6 项 DSH 已具备（部分是"有包但没装"），只有 Model Fallback 需要写代码。**

**实现 `src/model-fallback.ts`**
- 落点：`agent/request-error`（决定切不切 + 返回 retry）+ `agent/request`（把下次请求指向备用路由）
- 只对**可恢复**的失败切换：429 / 5xx / 401 / 403 / 408 / 传输层错误
- **不切**：上下文超限 / 配额耗尽 / 用户取消 / 内容拒绝 —— 换 provider 解决不了，切了会把真实问题掩盖成"所有 provider 都失败"
- `onSuccess` 重置切换额度但**不回退路由**（回到坏 provider 会再失败一轮）

**验收**：`test/model-fallback.mjs` **32/32**，全量 **258 项全绿**

**修掉的两个自身 bug**
1. `switches` 同时承担"计数"和"是否已切换"两个职责，`onSuccess` 归零后路由判断失效 → 拆开用 `cursor`
2. 超时码匹配漏了 `ETIMEDOUT`（里面是 TIMEDOUT 不是 TIMEOUT）

**待装（需要 YG 决定是否装，会改项目环境）**
- `dsh-hooks-claude-code` / `dsh-hooks-codex`：Claude Code / Codex hook 协议桥
- `dsh-subagent-claude-code` / `dsh-subagent-acp` / `dsh-subagent-codex`：外部 agent 作为 subagent

### 阶段 N：外部能力接入（已完成 ✅）

**已装并挂载（`/root/proj`，未触碰运行环境）**

| 包 | 状态 |
|---|---|
| `dsh-subagent-claude-code` | ✅ 已挂载，工具 `subagent_claude_code` 已注册并实测出现在模型工具列表 |
| `dsh-hooks-claude-code` | ✅ 已挂载，configPath 指向 `/root/proj/home/hooks.json`（文件不存在时安全降级，不触发钩子） |
| `dsh-hook-protocol` | ✅ 作为依赖装入 |
| `dsh-subagent-acp` | ⏸ 已装入但**未挂载** —— 它需要 `command`（要拉起的 ACP agent 可执行文件）才能通过配置校验，没有具体 agent 时挂上只会让条目校验失败。patch 里留了注释模板 |

**挂载方式（关键）**：插件从 profile 目录解析，仅装进 `dsh/node_modules` 不够。
必须在 `home/profiles/headless/node_modules/@deepseek-ai/` 下建 symlink，否则报
`Cannot find package ... imported from /root/proj/home/profiles/headless/`。

**验收**：`run.sh "x"` 启动零失败条目；带 key 起真实会话，模型确认工具列表含 `subagent_claude_code`。

**未装**：`dsh-subagent-codex`（缺 `@openai/codex` 这个较大的第三方依赖），需要时再补。

### 阶段 O：HITL 审核层（已完成 ✅）

**从 CyberStrikeAI 的 HITL 设计吸收三条原则**

来源：`docs/en-US/hitl-best-practices.md`。它的完整表述是
"planning, execution, human oversight, **evidence, and replay** in one auditable workspace"——
与我们在做的同源，其中审核层比我们成熟。

1. **硬底线是代码，不是提示词**：删除/格式化/写系统文件由 `ctx.tools.guard()` 直接拒绝，
   任何 reviewer（含 audit agent）无法覆盖。
2. **allowlist 只免审批，不授予权限**：白名单工具仍要过范围闸与预算闸。
   （对应 CyberStrikeAI 原文：allowlist "only bypasses HITL approval and does not grant additional access"）
3. **review-edit 只能收窄**：审核者可缩小目标后放行，但不能扩大攻击面。本实现暂未做 edit 模式，记录为后续。

**实现** `src/hitl.ts`
- `classifyRisk()`：read / write / destructive / c2。命令类工具（bash/pwsh）要解析命令内容，
  因为 `rm -rf` 和 `ls` 都是 bash
- `defaultHardFloor()`：只拦**确定灾难性**的操作（mkfs、dd 写裸盘、rm -rf /、fork bomb、
  写 /etc/passwd、grub-install），不做泛化"危险命令"匹配——后者会误杀正常渗透动作
- 落地分层：硬底线走 `guard`（同步、单调拒绝）；审批走 `tools/pre-execute`（返回 `ask`，
  由 `ctx.approval` 分派；无 approval 支持时自动降级为 deny）

**验收**：`test/hitl.mjs` **42/42**，全量 **300 项全绿**

**修掉的三处正则边界问题**
1. `-o` / `-e` 前面的 `\b` 不成立（`-` 不是单词字符），导致 `curl -o` 与 `nc -e` 漏判
2. `rm -r -f /` 中 r 与 f 分处两个 flag，单一正则会漏

## 6. 明天待办（YG 指定，2026-11-10 收尾时记）

### T1 中文输入不可用（最高优先级，阻塞日常使用）

现状：桌面快捷方式用 `xterm` 拉起控制台，xterm 不支持输入法（IME），无法输入中文。
候选方案：
- a) 换支持 IME 的终端：`xfce4-terminal` / `qterminal`（qterminal 在本机崩溃过，需先修 DBUS）
- b) 保留 xterm 但配置 `XMODIFIERS` / `GTK_IM_MODULE`，并确认系统装了 fcitx5 或 ibus
- c) TUI 菜单里避免中文输入（任务描述用编辑器写文件，菜单只做选择）

排查起点：`fcitx5-diagnose` 或 `ibus list-engine`，确认输入法框架本身是否存在。

### T2 界面太薄，不好用

现状：只有一个五项 TUI 菜单（`/root/proj/console.sh`），信息密度低、看不到状态。
方向：
- a) 复用 DSH 的 web 能力做一个小面板（隔离状态 / 测试结果 / claim 列表 / 队列）
- b) 或先做"状态页"：把 check.sh + 测试汇总 + claim/queue 状态渲染成一页 HTML，用浏览器看
- c) TUI 增强：进度条、颜色、实时刷新

注意：任何 web 界面都必须绑定到独立端口，不与运行环境的 3080 冲突（`run.sh` 已拦 profile=web）。

### T3 工程与技术问题（待 YG 具体化）

已记录但未解决的：
- 审核层最弱：只有结构性独立路径，挡不住系统性误判（需决定：独立模型盲审 / 人类签字）
- 重放挡不住"跑了但没测到东西"（`echo "PUT /api/user 200"` 能通过所有闸门）
- 端到端在真实会话下最后一次未完成（API 连接卡住，非代码问题）
- 尚未打包成可分发的 profile bundle（现为 dist 拷贝 + cordis.patch 挂载）
- internal-ad / crypto / post-exploit 三个方向没有可用 agent（见 §7）

等 YG 补充后逐条拆解。

## 7. 方向级 Agent 调度（阶段 P，2026-11-11）

### 7.1 为什么不用 skill 解决

用户否决过「写 skill 提质量」的路线。理由是站得住的：skill 是提示词，提示词约束不了执行。
「同一方向失败就换下一个」如果写在 skill 里，模型得自己记得失败过、记得换、记得换回来——
它没有失败率数据，凭一次失败换人且永不回头。这条必须由调度器执行。

### 7.2 分层

```
AgentRegistry      纯状态：方向 → 有序候选，失败计数、冷却、可用性
DirectionalDispatcher  编排：挑谁、何时放弃、尝试链怎么记
AttemptFn          执行：由调用方注入（生产是 QueueRunner，测试是假函数）
verdict 解析器     判据：把 agent 输出翻译成 found/clean/unknown
```

执行层注入是刻意的：调度逻辑要能在没有子进程的情况下测完，
否则每次改「何时降级」都要真跑外部工具，测试会慢到没人跑。

### 7.3 判定分四类（这是全层最要紧的地方）

| 结果 | 含义 | 换 agent？ | 计失败？ |
|---|---|---|---|
| `completed` | 拿到终态（有发现 / 没发现都算） | 否 | 否 |
| `agent-failure` | 工具自身故障：ENOENT、崩溃、超时、非零退出且无解析结论 | 是 | 是 |
| `inconclusive` | 跑通了但证据不足 | 是（要第二意见） | **否** |
| `refused` | agent 拒绝该调用（用法错误 / 本层不驱动） | 是 | **否** |

`inconclusive` 不计失败是刻意的：它说明这个 agent 能用只是这次没定论。
计入失败会在两次之后把可用 agent 冷却掉，方向整体停摆——这是真实系统里
「越重试越没结果」的常见成因。

### 7.4 实测接入状态（2026-11-11）

每个都真跑过，不是登记了事：

| 方向 | 可用 agent | 判定依据 | 验证 |
|---|---|---|---|
| mcp-security | `corvus` | 读 `report.sarif`，results 数量 + severity | 扫 fixture MCP server → 9 findings |
| ai-security | `promptfoo` | 读 `promptfoo.json`，stats 的 pass/fail/error | 1 pass / 1 fail → found |
| code-audit | `semgrep` | stdout JSON 的 `results` 数组 | 检出 subprocess 注入 |
| binary-reverse | `rabin2` | 解析 `-Ij` 的加固字段 | `/usr/bin/ls` → 保护齐全 |
| web-pentest | `nuclei` | JSONL 每行一个命中，零行即干净 | 本地靶子 `/.env` 泄露 → 命中 |

**三个方向刻意留空**：`internal-ad`、`crypto`、`post-exploit`。不是没找到工具——
本机有 `nxc` / `bloodhound-python` / `impacket-secretsdump` / `hashcat` / `john`——
而是它们全部缺**可编程判据**：要么输出是给人看的文本，要么必须对真目标（SMB/DC）
跑一次才能确认解析逻辑。按 §7.5 的教训，登记一个「能跑但永远 inconclusive」的候选，
等于让方向显示 ready 而实际给不出结论。现在的做法是让 `agent_directions` 显式标注
`NO-VERDICT`，把缺口摆在明面上。

接入这三个方向的前置条件：一个可复现的靶子（Samba / 域控容器 / hash 样本）
+ 对应的输出解析器。缺任一就不该登记。

已知不可用并如实登记原因的：`garak`（404MB 依赖装不完）、`pyrit`（subagent 类，本执行层不驱动）、
`strix`（沙箱+LLM 双依赖，无 verdict 解析器）、`toolfuzz`（库形态，需写 harness）、
`mcp-scan`（已改名 snyk-agent-scan，完整判定需 Snyk 云端）。

### 7.5 两条被实测纠正过的判断

**一、`reap` 和 `@mcp-scan/cli` 是我凭记忆写的，实测不存在。**
注册表里放不存在的东西，调度器会反复选中它反复失败，看起来像环境坏了。
现在每个条目要么本机已装并跑通，要么给出确切包名与安装命令。

**二、一个 agent 一个 venv。**
`semgrep` 与 `mcp-scan` 抢 `opentelemetry-api` 版本，装进同一个 venv 后 semgrep 直接 import 失败。
异构 agent 的依赖冲突是常态，共享 venv 等于给自己埋雷。semgrep 已迁到
`/root/proj/agents/venvs/semgrep/`。

### 7.6 渲染格式也是接口

第一版 `agent_dispatch` 的输出写成 `settled by rabin2 — found=false`，
模型把 `settled by X` 读成 `settled=X`，字段直接错位。
改成 `settled=true` / `found=false` / `by=rabin2` 的 key=value 形式后消失。
让人读着顺的句式，恰恰是模型最容易解析错的句式。

### 7.7 两个只在真实会话里暴露的接线缺陷

单测全绿、真机是 0。这两条都不是逻辑错误，是**接线错误**——最值得记的一类。

**一、`link` 传错了层级。**
`claim_id` 一路传到工具层，工具把 `link` 塞进 `installAgentTools` 的 options，
而真正在 submit 前建立 task→claim 关联的 `createQueueAttempt` 根本没拿到它。
现象：`agent_dispatch` 报 `settled=true`，`claim_query` 报 `evidenceCount=0`，
两边都不报错。单测覆盖了 `createQueueAttempt({link})` 这条路径，所以绿的；
漏的是 `index.ts` 里那行真实接线。

修法不只是补上参数，还要**让静默失效不可能**：`DispatchOutcome` 增加 `claimLinked`，
渲染文本固定输出 `claim_linked=true|false`；给了 claim_id 而执行层不支持时，
工具额外返回 `claim_note`。把「有没有真的链上」从不可见变成返回字段。

**二、schema 加了字段，render 没加。**
`claim_linked` 进了 output.schema，但渲染文本没带上，模型看到的是
`claim_linked=NOT_RETURNED`——它只能如实报告"没返回"。
这已经是同一个错误模式的第二次：上一版是 `settled by X` 被读成 `settled=X`。

结论：**渲染文本就是模型看到的那份接口，schema 不是。** 改 fields 必须同时改 render，
且 render 要有断言（现在 `agent-dispatch.mjs` 里有 8 条专门测它）。

### 7.8 判断与停手（2026-11-11 追加）

用户点出的问题：**「按固定队列一路跑」不是判断，是消耗。**
第一版确实是那样：priority 排好队，失败就换下一个，最多换五个。
两个毛病——不会挑更合适的，也不会在该停的时候停。

**一、先判形态，再挑 agent。**
同一个方向下的 agent 吃的东西根本不同：`corvus` 要一个能拉起的 MCP 命令，
`mcp-scan` 要一份 MCP 配置文件。给错了就算跑起来也是白跑。
所以目标先判形态（`url` / `directory` / `file` / `binary` / `command` / `host`），
候选声明 `accepts`，适配度优先、优先级次之。

真机上的差别很直接——给一份配置文件路径：

```
stop_reason=no-fit  shape=file  cost_spent=0
untried: corvus(fitness=0)
```

一个字节都没花，并且明确告诉了主控「corvus 吃不下这个形态」。
换成一味按 priority 派，就是让 corvus 去打一个它处理不了的输入，然后拿到一段 traceback。

**二、只有工具坏了才自动换。**
`agent-failure` 是机械替换，不需要判断，自动做。
`inconclusive`（跑通了但没定论）默认**不换**，直接交回主控——继续换等于用第二个工具的
偶然差异赌一个结论。想要第二意见就显式传 `second_opinion`。

这不只是省钱，也纠正了一个更隐蔽的错：把「没测出东西」当成「换个人再测」，
会让系统倾向于用重试次数冒充把握。

**三、五条止损线，任一条先到就停。**

| 止损线 | 触发条件 | 为什么必须存在 |
|---|---|---|
| `no-fit` | 剩余候选都不接受该形态 | 派出去的结果一定是失败，只是花时间证明已知的事 |
| `cost-budget` | 累计权重触顶（cheap=1/moderate=3/expensive=10） | 一次 LLM 驱动的扫描可能是静态检查的十倍代价，同一计数器下平权等于拿预算买噪音 |
| `fault-circuit` | 同一类故障连续两次（超时/缺失/崩溃各算一类） | 三个都超时说明问题在目标或网络，换第四个只是重演 |
| `deadline` | 墙钟触顶 | 单条派活不该无限期占住会话 |
| `max-attempts` | 尝试次数触顶（默认 2） | 默认值刻意保守：想多跑是显式动作，不是默认行为 |

`refused` 不计入熔断——它表示「这个 agent 不该干这个」，换人是对的。

**四、耐心也是 agent 的属性。**
每个候选声明 `defaultTimeoutMs`：`rabin2` 30 秒，`nuclei` 15 分钟，`strix` 30 分钟。
超时设错是隐形的——用 120 秒去卡一个正常要跑十分钟的扫描器，系统会把「慢」
记成「坏」，然后降级、熔断，把预算花在错误的地方。真机第一次跑 nuclei 就是这么
超时的，加上这个字段才正常。

**五、库默认必须等于工程默认。**
`DEFAULT_POLICY.stopOnInconclusive` 一度写成 `false`，而 `config.ts` 里是 `true`。
两边不一致的后果是：测试跑的是「会换」，线上跑的是「不换」——最容易漏的一类差异。
现在两处一致，且测试显式传 `secondOpinion` 才测换人路径。

## 8. 三公：主控内的职责分层（阶段 Q，2026-11-11）

### 8.1 它是什么，不是什么

三公是**职责划分**，不是三个模型、不是三个 DSH 实例。
判断依据全是结构化的——丞相看断言与缺口，太尉看方向与候选，御史看授权与熔断状态。
需要语义的部分（这个目标可能有什么问题）留给会话里的主模型。

不让模型当三公的理由很直接：**预算和次数是算出来的，不是聊出来的。**
一个会算错余额的御史大夫比没有御史大夫更糟，它会让「已批准」失去含义。

### 8.2 职责边界

| 角色 | 职责 | 落点 | 确定性 |
|---|---|---|---|
| 皇上（用户） | 目标、授权、Hint、高风险审批、最终裁决 | 人类 | — |
| 丞相 | 任务理解、情报整理、生成可验证假设 | `council/chancellor.ts` | 全代码 |
| 太尉 | 拆解任务、选执行体、维护状态、汇总 | `council/marshal.ts` | 全代码 |
| 御史大夫 | 授权范围、限流、超时、熔断 | `council/censor.ts` | 全代码 |
| — | 统一任务契约与 Adapter | `council/contract.ts`、`adapters.ts` | 全代码 |
| — | 证据归档与哈希 | `contract.ts` 的 `buildEvidenceManifest` | 全代码 |
| — | 人才档案 | `council/roster.ts` | 全代码 |

### 8.3 御史大夫为什么不管预算

用户明确要求把预算从这里摘掉。查了一圈业界做法，方向是对的：

- Microsoft agent-framework 把 **token budget 和 circuit breaker 做成中间件**（[issue #8862](https://github.com/microsoft/agent-framework/issues/8862)、[PR #5073](https://github.com/microsoft/agent-framework/pull/5073)），不是某个角色。
- 预算属于横切关注点：它作用于每一次调用，不归属于某一方。

拆开之后语义也清楚了：

| | 归谁 | 问题形态 | 处置 |
|---|---|---|---|
| 预算/次数 | 调度层（`agent-dispatch` 的 `costBudget`/`maxAttempts`） | 「这次值不值得再试」 | 可以加额度 |
| 授权/限流/熔断 | 御史大夫 | 「能不能碰这个目标」 | 授权问题一步都不能退 |

塞在一起会让「预算不够」和「越界」看起来是同一种拒绝，而它们的处置完全相反。
现在御史大夫只管四件事：`scope` / `rate-limit` / `breaker-open` / `timeout-too-large`。

一个容易写错的细节：**限流按已执行计数，不按已审批计数**。
审批通过但没跑的任务不占窗口，否则调用方批了不跑会留下幽灵记录，窗口莫名其妙被吃满。

### 8.4 学了什么

参照 [D-CIPHER (arXiv:2502.10931)](https://arxiv.org/abs/2502.10931)：Planner + 异构 Executor
+ 动态反馈循环，在 NYU CTF Bench / Cybench / HackTheBox 上是当时的 SOTA。
和我们的结构同构（丞相≈Planner，各方向 agent≈Executor），但有三点值得抄：

**抄了：异构 executor 必须真的异构。** 它的收益来自不同 executor 的能力差异，
而不是同一个 executor 多跑几次。我们对应的是「同方向多候选 + 按形态选」，
以及太尉的**轮转分配**——不轮转的话两条任务会全压给优先级最高的那个，
花两次钱买同一个结论，而号称的多候选一次也没被试过。

**抄了：反馈要闭环。** 它的 Planner 会被 executor 的结果重新驱动。我们的 `next_actions`
和 `MissionMemory` 做了第一层（汇总里直接给下一步动作），但还没有真正的「重规划」。

**没抄：Auto-prompter。** 它的作用是自动生成高质量初始提示，我们这边对应的是丞相的
假设生成规则——用结构（缺口/弱证据/上次卡点）而不是提示工程。结构判断可以复现，
提示工程不能。

### 8.5 工具补齐（Kali 现状盘点后）

Kali 主力本来就在。补的是能产出**结构化判据**的缺口：

| 工具 | 方向 | 状态 | 判据 |
|---|---|---|---|
| `checksec` | binary-reverse | 已装（apt） | `--output=json`，RELRO/canary/NX/PIE 任一为 no |
| `enum4linux-ng` | internal-ad | 已装（apt） | `-oJ` 报告里的 `sessions.null` / `sessions.guest` |
| `ROPgadget` | binary-reverse | 已装（venv） | 文本输出，暂无判据，未登记 |
| `arjun` | web-pentest | 已装（venv） | 参数发现不是漏洞，未登记 |
| `ropper` | binary-reverse | **装不上** | Python 3.14 下 `filebytes` 编译失败 |

两个「装了但没登记」的说明一个原则：**有二进制不等于有判据。**
登进注册表就会显示 ready，而实际跑完只能给 inconclusive，那是在骗调度器。

`internal-ad` 因此第一次有了可用 agent。它需要一个 SMB 靶子才能验证，
靶子脚本在 `fixtures/start-smb-fixture.sh`（只绑 127.0.0.1，故意配成
空会话 + guest 可访问 + 不强制签名）。

`crypto` / `post-exploit` 仍然空着：`hashcat`/`john` 是离线爆破，不构成
「测试目标实现」的判据。这个缺口如实留着，不塞占位。

### 8.6 实测

```
council_run(target=/usr/bin/ls, max_tasks=2)
  planned=2 executed=2
  binary-reverse outcome=settled agent=rabin2   detail=elf/x86: standard mitigations present
  binary-reverse outcome=settled agent=checksec detail=hardened: relro, canary, nx, pie
```

两条任务落在两个不同工具上——这是轮转分配生效的证据，也是「独立复核」的最小形态：
同一结论由两个不同实现得出，比同一个工具跑两遍强得多。

```
council_status()
  limits: scope=unrestricted rate=6/60s breaker=3 max_timeout=1800000ms
  roster: rabin2 runs=4 settled=4 / checksec runs=1 settled=1
```

御史大夫现在只报这四项，不再有预算字段。

## 9. 误报账本（阶段 R，2026-11-11）

### 9.1 为什么需要它

证据链能验证两件事：证据相关（锚点匹配）、证据可复现（严格摘要重放）。
两件都成立，结论仍可能是错的——verdict 解析器有 bug、模板过期、目标本身就是测试页。
**`replay` 保证的是重跑得到同样输出，不是这个输出说明有问题。**

要真正解决只能引入独立仲裁者（另一个模型盲审，或人签字），那是流程决策。
在此之前代码能做的是**把数据攒出来**：谁报的发现后来被推翻了。
等到有了真实误报率，「要不要加盲审」「加给谁」就不是拍脑袋。

### 9.2 三条口径，每条都在防一种失真

| 失真方式 | 后果 | 口径 |
|---|---|---|
| 按执行次数算 | 同一工具跑三次变成三次判断 | 按 claim 计数 |
| 没归因也记黑账 | 一条 claim 里正确的工具跟着背锅 | 只统计有归因的推翻 |
| 未定论进分母 | 误报率被稀释成好看的样子 | 分母只含 confirmed + refuted |

第四道保护：样本不足 5 条不给比率。三条里错一条不是 33%，是样本不够。
没有比率的行会写明原因，而不是显示一个 `0%` 让人误以为它很准。

### 9.3 归因是覆盖，不是累加

`claim_refute` 的 `blame_agent` 第二次调用会**替换**上一次，不是追加。
理由：一条 claim 只被推翻一次，之后都是修正。累加会让「记错了」变成
「永远错下去」——误报账一旦写错就再也洗不掉，而这个账本的全部价值就在于可信。

真机上这条设计被验证过：我让模型给 rabin2 记一笔账（说它报了假发现），
模型拒绝执行，理由写得很准——

> rabin2 这次并没有给出坏证据：它报告的是 "elf/x86: standard mitigations present"，
> 调度返回 found=false。该 claim 是我自己提的未证伪假设，被证伪说明的是假设不成立，
> 而不是工具出错。

它把这次记为 `unattributed_refutations=1` 而不是乱记黑账，正是设计意图。
工具描述里现在写明了这条边界：「不要为你自己编的假设去怪工具」。

### 9.4 呈现

`council_status` 增加 `precision` 段：

```
precision:
  rabin2 reported=2 confirmed=0 refuted=0 open=2 fpr=n/a (no settled claim yet — nothing to score)
unattributed_refutations=1
precision_note: 有 1 条 claim 被推翻但没记归因；这部分误报统计不到
precision_note: 目前只有 1 条 claim 有了定论，误报率还不能用；继续积累到 5 条再看
```

`council_run` 的 `next_actions` 也会带上同样的提示——报了一个发现、这条 claim
又被推翻，这个反馈必须当轮就到达，不该等人再去问一次 status。

`claim_query` 的投影现在带 `tool` 和 `blame`：不知道证据是哪个工具产的，
就没法判断该不该信它，也没法在推翻时给出归因。

### 9.5 只提示，不自动弃用

`precisionActions` 在误报率超阈值时会说「优先查判据（verdict 解析器 / 模板是否过期），
而不是直接弃用」——误报常常是解析器的错，不是工具的错。
样本刚够就开始拉黑一个工具，等于用五条数据决定一个长期决策。

## 10. 外部项目调研与吸收（2026-11-11）

### 10.1 盘点

| 项目 | 星 | 语言/许可 | 定位 | 处置 |
|---|---|---|---|---|
| [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | 34.0k | Go / MIT | 全自主多 agent 渗透系统 | 借鉴（服务架构重，不接） |
| [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 13.5k | Python / MIT | MCP 暴露 150+ 工具 | 已登记为 mcp 候选，依赖未起 |
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | 10.0k | Python / Apache-2.0 | LLM 漏洞扫描 | 已在注册表；404MB 依赖装不完 |
| [samugit83/redamon](https://github.com/samugit83/redamon) | 3.4k | Python / MIT | 攻击面图谱 + Kali 沙箱 + 审批门 + 自动修 PR | **借鉴覆盖戳与资源治理** |
| [Adaptix-Framework/AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) | 3.9k | C++ / **GPL-3.0** | 模块化 C2 | 不接（传染性许可，且是 C2 框架） |
| [GH05TCREW/pentestagent](https://github.com/GH05TCREW/pentestagent) | 3.3k | Python / MIT | 黑盒测试 agent 框架，LiteLLM + MCP | 借鉴 playbooks/knowledge 分层 |
| [AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) | 0.6k | Go / **AGPL-3.0** | 自主渗透平台（ARTEX 二次开发） | 不接，且与 ARTEX 同类，设计参考即可 |

### 10.2 吸收了什么：覆盖账本

redamon 的 `graph_db/coverage_stamps.py` 解决了一个我们正踩着的坑。
它的注释里有一条原则值得原样搬：

> 没有 stamp，但同项目别处有 stamp → 这个资产「未扫描」；
> 整个项目一条 stamp 都没有 → 只能说「覆盖未记录」，**永远不能说「未扫描」**。

这和我们 claim 里 `inconclusive ≠ clean` 是同一条：**没有数据不等于阴性**。

落地为 `src/coverage.ts`，四态：
`covered` / `partial` / `not-scanned` / `not-recorded`。

- **自动记账**：太尉每次执行后落戳（asset × 方向 → 状态 + 输入 + 输出 + 原因），
  不靠模型手动填。让模型自己填，它会在「还没测」和「测了没发现」之间含混过去。
- **`no-input` 单独一档**：没东西可查不等于查过没问题，判定时按「未扫描」处理。
- **`coverage_view` 只读**：查缺口，不做判断。

这条直接对上这次实战的病根：六轮分析全压在同一条路上，没有任何机制说
「A、B、C 都试过了，还剩 D」。人靠记忆、模型靠上下文，而上下文会被压缩。
账本不会。

### 10.3 没接的及理由

- **AdaptixC2 / antifox**：GPL-3.0 / AGPL-3.0 传染性许可。前者的定位是 C2 框架，
  后者是 ARTEX 二次开发（此前已记录 ARTEX 只做设计参考）。
- **pentagi**：Go + GraphQL + Neo4j + Langfuse 的服务栈，接入成本远高于它能提供的能力，
  而它的核心（多 agent 编排）我们已经有了。
- **pentestagent**：值得后续评估。它的 `playbooks/`（可复用作业手册）和
  `knowledge/`（知识库）分层，正好是我们 `plan` 那一层缺的东西——现在丞相每次从零推假设，
  没有沉淀。
- **hexstrike / garak**：登记在册，卡在依赖（前者要起 MCP 服务，后者 404MB 下不完）。

### 10.4 待办

- 丞相读覆盖账本，按缺口排序假设（现在账本只被观测，还没进入 `assess`）
- pentestagent 的 playbooks 分层，考虑做成「作业手册」而不是知识库

## 11. ARTEX 评估与部署（2026-11-12）

用户决定 AGPL 可以自用后重新评估。结论：**用原版，不用二开**，并且已经本地跑通。

### 11.1 原版 vs 二开

| | [原版 Hinln/ARTEX](https://github.com/Hinln/ARTEX) | [二开 antifox](https://github.com/AntiFox-AI/antifox) |
|---|---|---|
| 版本 | v0.3.15 完整备份 | 从 ARTEX 二开 |
| ★ / 最后推送 | 1533 / 2026-10-08 | 578 / 2026-10-31 |
| 总文件 | **601** | 474 |
| `server/` | **103** | 45 |
| `engine/` | 0（在 server 内） | **57**（拆出来） |
| `evidence/` | **3** | 0 |
| `report/` | 2 | **14** |
| `web/` | 210 | 181 |

二开是**重构**（engine 从 server 拆出，57+45≈103），不是简单加功能；但它砍掉了
`evidence/`，`server/` 少一半。对我们最重要的是证据模型，而那块只在原版里完整。
**选定原版。**

### 11.2 部署（已跑通）

Docker Hub 直连超时、daocloud 加速器不在白名单——镜像拉不到。改源码编译：

```
apt-get install golang-go        # go1.27.3
createdb artex                  # PostgreSQL 18 已在机器上
go build -o artex ./cmd/artex   # GOPROXY=goproxy.cn，约 2 分钟
./artex                          # 监听 :8787 (API) / 127.0.0.1:8788 (流量代理)
```

后端是纯 JSON HTTP API，**不依赖前端构建产物**（`main.go` 里没有 embed），
所以只跑后端就够。LLM 走 `ARTEX_LLM_BASE_URL` 指向 DeepSeek 的 OpenAI 兼容端点，
启动日志确认 `LLM configured from env: openai / deepseek-flash`。

### 11.3 可驱动性（已验证）

```
POST /api/auth/init {"password": ...}        → JWT
POST /api/tasks    {"goal","description","seed_first_intent","coverage_enabled"}
GET  /api/tasks
DELETE /api/tasks/{id}
```

实测建单/查询/删除全通。`createTaskReq` 里有几个字段值得注意：
`seed_first_intent`（跳过 planner 直接下发种子意图）、`coverage_enabled`、
`intercept_rules`（任务级资产拦截）。

### 11.4 值得吸收的三处

**一、证据的 role 与版本**（`docs/漏洞流量证据.md`、`evidence/store.go`）

它的 finding 证据绑定到**真实流量快照**，每条带 `role`：
`baseline`（正常对照）/ `proof`（漏洞证明）/ `verification` / `supporting`，
并且报告必须声明 `evidence_version`——生成期间证据变了就拒绝旧版本写入
（`409`），正文按 SHA-256 存 blob，快照不可更新、校验不一致时读取失败。

我们缺的正是 `baseline`：**证明漏洞需要「正常情况」作对照**。
我们的 evidence 只有 `{ref, pathKey, source, relevance}`，没有角色区分，
一条「越权访问成功」的证据和一条「正常请求」的证据看起来一样。

**二、`list_untested_assets`**

它的覆盖度是一等公民，有专门的工具列出未测资产。我们刚做的 `coverage_view`
只到查询，还没有把它接进丞相的假设排序。

**三、`intent_intervention`**

人给暂停中的 worker **注入一句话**，走 HTTP API，复用现有 pause/resume 机制
（`ExecuteWithMessage`），在独立 goroutine 跑不占 worker 池。
我们的 HITL 只有「批准/拒绝」，缺「指导」这个动作。

### 11.5 已落地（2026-11-12）

**一、`baseline` 证据角色**（`src/provenance.ts`）

`evidenceSchema` 加 `role: 'proof' | 'baseline'`，缺省视为 `proof`——
历史数据都是当证明用的，不能因为加字段就改写它们的语义。

关键改动在 `deriveStatus`：**只数 proof 路径**。
之前两条正常请求就能把断言推到 `confirmed`，那正是这套模型要防的事。
`claim_evidence` 工具新增 `role` 参数，`claim_query` 输出现名为 `paths: {proof, baseline}`。

实测瓶颈：`claim_evidence` 的相关性校验会先挡（`/tmp/a.log` 这种不存在的 ref
过不了锚点匹配），所以真机上 `role` 的生效路径要在有真实证据时才看得到；
逻辑本身由 `test/baseline-role.mjs`（12 条）覆盖。

**二、ARTEX 接成专项执行者**（`src/council/artex-adapter.ts`）

- 注册为 `agent` kind 的执行体，把原来的空壳换掉
- `POST /api/tasks` 建单（`seed_first_intent: true` 跳过它的 planner——规划在我们这边做完了）
- 轮询 `GET /api/tasks/{id}` 到终态，从 `TaskDTO.findings` 取分档计数
- **证据留在 ARTEX 侧**（含流量快照与哈希），不复制一份过来——两份副本迟早不一致
- 401 自动重登一次，连续 401 不再重试（那是密码或权限问题，重试只是重复同一个错误）

`Marshal.plan` 的选择顺序也改了：本地 CLI 优先，外部执行体只在本地没有能吃该形态的
工具时顶上。反过来做会让每条任务都先把目标交给外部平台，本地工具形同虚设。

运行时确认两个 adapter 都在：
```
adapter code-tool: 本地确定性工具（nuclei/semgrep/corvus/rabin2 等）
adapter agent: ARTEX 专项执行者（外部服务，自带流量证据与覆盖度）
```

**三、ARTEX 服务状态**

常驻 `:8787`（API）/ `127.0.0.1:8788`（流量代理），PostgreSQL 18 本地库 `artex`，
Go 编译产物在 `/root/proj/agents/artex/ARTEX-main/artex`。
停止：`pkill -f ARTEX-main/artex`。

### 11.6 收尾的三处（2026-11-12）

**一、丞相读覆盖账本**

`Chancellor` 现在拿得到 `CoverageLedger`。已在某方向完整覆盖过的资产，
不再生成「存在弱点」这类假设，而是进 `skipped` 并说明原因；
`partial` 的会在 rationale 里注明「上次只做到部分覆盖，这次补完」。

这条直接对上实战的病根：六轮全压在同一条路上，因为没有任何东西记得「这条已经走过」。

**二、缺对照变成可见信号**

- `claim_query` 的投影在「有 proof 无 baseline」时给 `hint`
- `submit_answer` 的 `judgeAnswer` 返回 `warnings`（与 `missing` 分开：
  missing 是「现在还不行」，warnings 是「行了但不够硬」）

不强制补 baseline——RCE 回显、服务崩溃这类漏洞没有「正常情况」可比。

**三、两个真 bug（都是模型在真机上发现的）**

1. `claim_evidence` 的 `role` 参数只加进了 schema 没加进 parameters，
   模型以为工具没这个能力，把 `role=proof` 写进了 note。
   —— 这是同类疏漏的第三次（前两次是 link 传错层、render 漏字段），
   现在 `test/wiring.mjs` 有一条专门断言工具参数存在。
2. 补 baseline 时被去重吞掉：`attach` 的去重没带 `role`，
   同 ref 同 pathKey 的 baseline 被当成重复证据静默丢弃。
   「补了对照却被吞掉」比没补更糟——模型会以为已经补过了。
   去重键现在是 `(ref, pathKey, role)`。
3. 附带一个：`{ hint: undefined }` 不是合法 JSON，导致**证据最齐全的那些 claim**
   反而序列化失败。改成返回空对象。

真机验证：`paths: {"proof": 1, "baseline": 1}` + `hint: 无`，
且模型自己正确解释了「同一 pathKey 仍只算一条独立路径，所以状态还是 partial」。

### 11.7 收尾第二批（2026-11-12）

**一、外部指导注入**（`src/guidance.ts`，对应 ARTEX 的 `intent_intervention`）

人在会话运行期间递一句话进去，下一轮 `pre-step` 注入：

```
echo '别用枚举，改成约束求解' >> <workspace>/.guidance
```

设计做到最笨：**一个文件**。消费用 rename 到临时名再读——读到的要么是完整内容，
要么什么都没有；直接 read+truncate 会在两者之间留一个窗口，那个窗口里崩溃就丢消息。

为什么不做成 RPC/队列/socket：那些都要维护连接和状态，而这个东西的使用频率是
「人工偶发」。用文件，断了不丢、重启还在、任何工具都能写。

**这个能力是整个实战里我最缺的**：六轮分析，每次想推它一把都得 kill 重开，
上下文全丢，前面几十分钟的推理作废。

真机验证：会话在跑 `sleep 45`，第 30 秒写入一句，模型当轮就收到并原样复述。

**二、`crypto` 方向落地**

`sslyze`（`--json_out`，机器上已有）。判据只看**能直接导致攻击的**配置缺陷：
废弃协议（SSL 2/3、TLS 1.0/1.1）、Heartbleed、ROBOT、CCS 注入、压缩（CRIME）、
客户端触发重协商 DoS。

刻意不把「弱密码套件」算一条——几乎所有真实服务都有几个 3DES/CBC 套件，
把它们算成发现会让这个方向噪音大于信号。

e2e 用本地 `openssl s_server` 做靶子，实测报出 `TLS 1.0 enabled, TLS 1.1 enabled`。

**三、`post-exploit` 方向登记**

`AdaptixC2` 登记为候选，但**明确标注未接通**：需要自行编译 C++/Qt 依赖的
server 与 agent，且要先有一个已控主机作起点；它产出的是「会话」不是「发现」，
本层没有对应判据。`priority: 80`——C2 是重活，不该在任何情况下被优先选中。

七个方向现在都有登记，其中六个有出判据的 agent。

## 12. 副 agent 扩充（2026-11-12）

### 12.0 先认一个错

前一轮我把 strix/CyberStrikeAI 这些「登记进注册表 + 标 MISSING + 写 requires」
当成了采纳。那不是采纳，是记账——`agent_directions` 里它们一直显示 `MISSING`，
从来没有被真正驱动过。这一轮改成实办。

### 12.1 strix：真正接通了

之前卡在三点，现在都解决了：

**镜像**。默认从 `ghcr.io` 拉，直连超时。镜像名可以用 `STRIX_IMAGE` 覆盖，
所以改用 `ghcr.nju.edu.cn/usestrix/strix-sandbox:1.3.0`（南大镜像），
4.07GB 落盘成功。

**LLM 配置**。strix 只认环境变量或 `--config` 指向的 JSON（结构是 `{"env": {...}}`）。
不能为它污染全局 env——同进程里别的 agent 也在用。改成每次派活现写一份到证据目录。

**输出位置**。它把结果写进 `<cwd>/strix_runs/`，没有输出目录参数。
给 `AgentCandidate` 加了 `ownWorkdir`：这类候选在自己的证据目录里跑。
不加的话并发派活会写进同一个 runs 目录，verdict 读到别人的结果。

实测跑通（`--max-turns 5 --max-budget 0.3`）：
```
Penetration test completed · Vulnerabilities 0 · Cost $0.0360
Output  strix_runs/host-docker-internal-18081_2f0c
```

**判据的坑**：真实产物是 `findings.sarif`（不是源码里的 `vulnerabilities.json`），
而且 SARIF 里混着两类东西——`strix-coverage/*` 的 `level: none` 条目是「这个方面
查过了/建议复查」的覆盖度记录，**不是发现**。不过滤的话每轮都会报一堆假发现。
现在的 verdict 会排除它们并说明排除了几条：

```
verdict: {"found":false,"detail":"0 finding(s), 7 coverage note(s) excluded"}
```

已知限制：目标若是 `127.0.0.1`，容器内要能回连宿主，否则空跑（实测报
`Target unreachable`）。真实渗透目标是远程 IP，不受影响。

### 12.2 rea（morluto/rea，MIT，★45 万）

`npm i -g rea-agents`（6.7.0），同时提供 CLI 和 MCP server。
CLI 面很完整：`analyze` / `analyze-javascript-application` / `analyze-web-bundle` /
`capture-browser-scenario` / `compare` 等，输出带 `--filter-output`（结构化 key path）。

原生二进制分析需要 Ghidra/IDA/Hopper 之一做引擎，当前都没有，
`rea analyze /usr/bin/ls` 报 `provider_unavailable` 并列出四个 provider 各自缺什么
（诊断质量很高，还带 `rea doctor`）。静态 JS/Electron 分析不需要引擎。

已登记为 `binary-reverse` 候选（priority 30），`requires` 写明引擎依赖。

### 12.3 CyberStrikeAI（Apache-2.0，Go，★8.6k）

从源码编译成功：`go build -o cyberstrike-mcp ./cmd/mcp-stdio`（22MB）。
它有两个入口：`cmd/mcp-stdio`（MCP stdio）和 `cmd/server`（HTTP）。
结构里有 `roles/`、`knowledge_base/`、`skills/`、`mcp-servers/`、`plugins/`
——是完整平台，和 ARTEX 同类。

**未接通**：我们的 `mcp` kind 目前只是登记，没有 MCP 客户端实现。
要接它（或任何 MCP server）得先写那一层。

### 12.4 其余评估

| 项目 | 形态 | 结论 |
|---|---|---|
| `shannon` ★51.8k AGPL | npm `@keygraph/shannon` 3.5.1，monorepo | 有包可装，AGPL；未装 |
| `cai` ★9.8k | Python framework，`agents.yml` 配置驱动 | 是框架不是工具，定位与我们重叠 |
| `AdaptixC2` GPL-3.0 | C++/Qt，C2 server + agent | 已登记，需自编译且要先有立足点 |

### 12.5 现状

```
可用 9 个：promptfoo corvus semgrep checksec rabin2 rea sslyze enum4linux-ng nuclei
方向覆盖：code-audit 1/1  crypto 1/1  internal-ad 1/1
          binary-reverse 3/4  web-pentest 1/2  mcp-security 1/2  ai-security 1/3
          post-exploit 0/1
```

`binary-reverse` 现在有三个（rabin2 / checksec / rea），是覆盖最厚的一向。

### 12.6 MCP 客户端层（2026-11-12 补齐）

之前 `mcp` kind 只是登记，没有任何驱动代码——CyberStrikeAI 编译好了、
rea 装好了、hexstrike 登记了，全都停在「用不上」。

`src/mcp-client.ts`：行分隔 JSON-RPC over stdio，只实现四个方法
（`initialize` / `notifications/initialized` / `tools/list` / `tools/call`）。
不实现 resources/prompts/sampling——多实现一个就多一处会和上游产生偏差的地方。
stderr 不参与协议流，所以 stdout 可以是纯协议。

`src/council/mcp-adapter.ts`：把 MCP server 包成统一执行体。
- 连接按 command 串缓存复用（CyberStrikeAI 是 22MB 的 Go 二进制，每次派活重启太浪费）
- 连接断开就清缓存，否则后续每次派活都在死连接上失败
- 候选 id → 工具绑定（`bindings` 表）：一个 server 几十个工具，候选只声明「我用哪个」
- 没有 verdict 的工具如实报 `inconclusive`，不猜

**顺带修了一个设计缺陷**：`Marshal.plan` 之前写死 `kind: 'code-tool'`，
所以 mcp 和 agent 类的候选永远轮不到——注册了等于没注册。
现在按候选**自己声明的** kind 派活（`cli→code-tool`、`mcp→mcp`、`subagent→agent`）。
`TaskContract` 也加了 `agentId`，adapter 靠它知道该调哪个工具。

### 12.7 CyberStrikeAI 实测

`cyberstrike-mcp -config <example.yaml>` 起来后 MCP 握手正常，暴露 **81 个工具**：
`ghidra` / `linpeas` / `sqlmap` / `nmap` / `dirsearch` / `binwalk` / `ropgadget` /
`libc-database` / `ffuf` / `paramspider` / `waybackurls` / `responder` / `falco` …… 
其中 **ghidra** 补上了我们缺的深度反编译，**linpeas** 填了 `post-exploit` 的空方向。

注册四个候选（都走 mcp kind）：
`cyberstrike-sqlmap`（web-pentest）、`cyberstrike-dirsearch`（web-pentest）、
`cyberstrike-nmap`（internal-ad）、`cyberstrike-ghidra`（binary-reverse）。

端到端实测（nmap 扫本机）：

```
outcome: settled  found: true
detail: 22/tcp ssh, 445/tcp netbios-ssn, 5432/tcp postgresql
```

中间踩过一个参数坑：`timing: 'T4'` 被 nmap 拒（要 `4` 或 `Aggressive`），
错误原样从 MCP 传回来——这本身说明链路是通的。

### 12.8 待办

- shannon 的实际安装与评估（npm `@keygraph/shannon` 3.5.1）
- ARTEX（agent kind）与 strix（code-tool, ownWorkdir）同向重叠：都能测 web，
  谁先上该由代价和形态决定，现在没有仲裁规则
- `cyberstrike-dirsearch` / `cyberstrike-ghidra` 还没有 verdict，暂时只能出 inconclusive

## 13. 从 cai 借鉴的两处（2026-11-12）

### 13.1 看完了什么

`aliasrobotics/cai`（★9.9k）是 Python agent 框架 + 一整套预置 agent
（redteam / blueteam / bugbounty / dfir / compliance / memory_analysis 等 39 个）。
逐项对比后，只有一处是能直接落地的工程改进。

### 13.2 采纳：工具可用性依赖凭据

它的 `tool_registry.py` 里有 `TOOL_REQUIRES_KEY`：
`shodan_search` 要 `shodan_api_key`、`c99` 要 `c99_api_key`——
**没有 key 的工具根本不暴露**。

我们的 `probeAgents` 只检查二进制在不在。于是 `agent_directions` 对
「装了但没配凭据」的工具只能说一句 `MISSING`，那等于让人去猜。

现在 `AgentCandidate.requiresEnv`：**外层 AND、内层 OR**。
`[['LLM_API_KEY','OPENAI_API_KEY']]` 表示两个有任意一个就行——
组内用 AND 会把本来能跑的工具误判成不可用，这个错误比漏报更难发现。

`agent_directions` 现在区分：
- `MISSING` —— 二进制不存在
- `NO-CREDENTIAL` + `missing_env: ["LLM_API_KEY|OPENAI_API_KEY"]` —— 命令在、凭据缺

顺带修了 `probeAgents` 对 mcp 候选的判断：之前把所有非 cli 类一律判死
（那是 MCP 层写出来之前的结论），现在 mcp 候选通过 `probeCommand`
指向 server 二进制来探测。

### 13.3 没采纳，但记下理由

**`operational_handoffs.py`（handoff 转移控制权）**。它用的是 OpenAI Agents SDK
的 handoff：agent A 把控制权交给 agent B、A 退出，B 接着干。这和我们的
「主控 + 确定性 Marshal 派活」是两种架构：handoff 把调度决策交回模型，
我们的底线是调度和预算由代码算。不采纳。

**`AGENT_TOOL_CATEGORIES`（角色 → 工具类别）**。redteam 能碰
`recon/exploitation/lateral_movement/privesc/web/c2/network`，blueteam 能碰
`recon/defensive/monitoring`。这是按**角色**分层，我们是按**风险**分层
（HITL 的 read/write/destructive/c2）+ 按**方向**分组。两者互补，
但当前没有「红队 agent 不该碰防守工具」的实际需求，先不做。

**`continuation.py`（用 LLM 生成续跑建议）**。agent 停下时再调一次模型
判断「接下来该做什么」。和 13.3 第一条同理：这件事我们的停滞检测已经在做，
依据是调用指纹和搜索特征，可复现；换成模型判断就不可复现了。

**`unified_context`（跨 agent 共享原始对话）**。我们有更好的等价物：
共享的是结构化的 claim / evidence，不是原始对话。后者会让上下文膨胀且互相污染。

**`caibench`（基准测试）**。除非要对外证明效果，否则是负担。

### 13.4 现状

```
web-pentest 4/4   binary-reverse 4/5   internal-ad 2/2   code-audit 1/1
crypto 1/1   ai-security 1/3   mcp-security 1/2   post-exploit 0/1
```

`web-pentest` 现在是 4/4 满的（nuclei / strix / cyberstrike-sqlmap / cyberstrike-dirsearch）。
778 断言全绿。

## 14. 补四个结构性缺口（2026-11-12）

评估出来的四个缺口，一次做完。

### 14.1 资产模型（`src/asset-store.ts`）

之前 nmap 报 `22/tcp ssh, 445/tcp netbios-ssn, 5432/tcp postgresql`，
这三个服务就停在那条 detail 字符串里。下一轮派活没人知道 445 已经开着——
除非模型自己去翻日志想起来。真实渗透里「看到 445 → 转 SMB 枚举 → 拿共享」
靠的是资产之间的父子关系，不是记忆。

落成 `AssetStore`：`host → service / endpoint / share / file`，JSONL 持久化。
`extractAssets()` 按方向解析工具输出（nmap 端口行、nuclei 的 url、enum4linux 的
shares、crypto 的 host:port），**认不出格式就返回空数组**——猜出来的资产比没有更糟。

两个设计点：
- 同一方向多次检查取**最强**结论。后来的一次 clean 不该覆盖之前的 finding。
- 丞相现在读资产库：已发现的服务里，445/139 推 `internal-ad`、443/8443 推 `crypto`、
  80/8080/8000 推 `web-pentest`。只认这几个能直接推出方向的端口，
  不做通用端口字典——那会生成一堆没有依据的假设。

### 14.2 接线自检（`src/wiring-check.ts`）

上一轮四个接线 bug 里，`rea` 没有 `invocation` 是**纯静态可查**的——
注册了、probe 认为可用、派活时才 refused。现在启动时跑一遍：

```
cli 无 command            → error
cli 无 invocation 也无 requires → error    ← rea 那次的原型
mcp 无 probeCommand       → error           ← 会被 probe 判成「本层不驱动」
verdict 不是函数          → error
subagent 无 provider      → warn
requires 短于 8 字        → warn（说不清要补什么）
```

第一版把 mcp 也要求 invocation，那是照搬 cli 的规则——mcp 的调用走 adapter 的
id 绑定，不经过 `buildArgv`，四小时内误判了四个候选。

### 14.3 found 分档

`found: boolean` 装不下真实情况：nuclei 的 12 条 info 指纹、checksec 的「缺 canary」、
SQL 注入，混在一起会让误报账本和覆盖统计全失真。现在三档：

| 档 | 含义 | 例子 |
|---|---|---|
| `finding` | 可直接利用 | sqlmap 注入点、enum4linux 空会话、Heartbleed、promptfoo 断言失败 |
| `exposure` | 暴露面/配置 | nuclei 的 info/low、缺加固、危险导入、废弃 TLS 协议 |
| `clean` | 查过没问题 | 加固齐全、断言全过 |

贯穿到 `TaskResult.findingClass` → `MarshalSummary.findings/exposures/cleans` →
`council_run` 的 `by class:` 行。`next_actions` 也分开了：finding 走证据登记，
exposure 明确说「本身不构成漏洞，价值在于指向下一步该往哪打」。

### 14.4 验证层（`verificationOf`）

`replay` 只能证「可复现」——`echo "PUT /api/user 200"` 也能通过严格摘要。
现在分三档，不压成一个布尔：

| 档 | 判据 | 能说明什么 |
|---|---|---|
| `none` | 没重跑过 | 等于「工具这么说」 |
| `reproducible` | 严格摘要重放通过 | 同一条命令再跑得到同样输出。**证不了真能打** |
| `calibrated` | 严格重放 + 检测器对照 | 尺子准（工具在已知样本上判对了）。§14.6 |
| `cross-checked` | 严格重放 + baseline 对照 | 唯一能说「这个响应不正常」的档位 |

`submit_answer` 现在返回 `verification` 字段。缺重放、缺 baseline、缺校准是**三条独立警告**，
因为它们补的方式不同。`claim_query` 的投影也带 `verification`——模型不该走到最后一步
才知道自己只有 `reproducible`。

### 14.5 资产 ↔ 断言双向关联

原来的资产库只能「从扫描结果推出资产」，回答不了反向问题：「这台 445 端口上，
我们到底确认了什么」。而攻击链恰恰是从「某资产已有确定结论」出发的。

- `Asset.claimIds`：资产指向涉及它的断言
- `AssetStore.byClaim`：反向索引，`assetsOf(claimId)` 直接给出资产清单
- `Claim.assetIds`：断言指向它涉及的资产（借鉴 ARTEX `findings.asset_ids` 的多对多）
- `claim_evidence` 接 `asset_ids`，写回时双向登记
- `asset_list` 支持 `claim_id` 过滤
- `claim_query` 投影带 `assetIds`

### 14.6 检测器校准（`src/control-check.ts` + `src/control-tools.ts`）

上一版遗留的真问题：`cross-checked` 只有 web 类 claim 能达成。二进制加固、TLS 配置
这类方向**根本没有「目标正常态」可比**——你没法让同一个二进制「加固着」再跑一遍当对照。

补的不是 baseline，是**尺子校准**：拿一个已知加固齐全的样本（`/usr/bin/ls`，
实测 `relro=full canary=yes nx=yes pie=yes`）跑同一条检测命令，它必须报 clean。

三个结果分开，因为处理方式完全不同：

| 结果 | 含义 | 处理 |
|---|---|---|
| `trusted` | 对照样本报 clean | 检测器对目标的结论可用 |
| `untrusted` | 对照样本也报问题 | **检测器坏了**，它对目标的全部结论作废 |
| `error` | 没跑起来（缺装/超时/崩） | 既不能信，也不能当成「目标干净」 |

`untrusted`/`error` 绝不能读成「没发现问题」——这是这类检查最容易写错的地方：
检测失败被当成脆弱性为零，报告里什么都没有还成了好结果。

工程闭环（三道闸，都在代码里）：

1. `detector_check` 工具跑对照，结果进 `ControlLedger`；返回的 `ref` 形如
   `control:checksec@trusted:canary=yes,...`
2. `claim_evidence(role='control', ref=<上面那串>)` 才能附校准。手写的 ref 被
   `controlGateOf` 拒——否则任何断言都能凭空升到 `calibrated`
3. 闸门查账本：该工具必须是 `trusted`。检测器在已知加固样本上都报缺防护，
   它对目标的「缺防护」是它自己的毛病，这种输出进报告比没有输出更糟

`calibrated` 与 `cross-checked` 互不替代：有 baseline 无 control → `cross-checked`
（目标对照过，工具坏没坏不知道）；有 control 无 baseline → `calibrated`
（工具校准过，目标没有可比正常态）；两者都有 → `cross-checked`，control 作为附加说明保留。
`control` 证据**不计入** `independentPaths` / `toolPaths` / `replayPaths`——它跑的是
本地样本，算进去就是凭空多一条独立路径；它单独也不能把任何断言推向 confirmed。

`AgentCandidate.control` 现在只在 `checksec` / `rabin2` 上声明。没声明的候选
（`sslyze` 没有简单对照、`radare2` 的危险导入本身就是信息）留空——宁可没有校准，
也不要一个假校准。

### 14.7 「每个副 agent 真能用」——逐个验证暴露的五个缺陷

`test/each-agent.mjs` 逐个派活，五个 FAIL 都是真实的接线/语义问题，不是测试写错：

**a. nuclei 的时间账没人算过。** 全量 11315 模板 / 21087 请求，本机 RPS ~210，
对单个 URL 要 430s——而它的 `defaultTimeoutMs` 是 900s，看起来「够用」，
实际上任何 3 分钟预算的编排都会把它砍在半路。用 `-severity high,critical`
收到 4532 模板 / 75s（`medium` 再加到 119s）。选 high/critical 作默认，
并在 capability 里**写明 medium/info 不覆盖**——覆盖边界要写在牌面上，
不能让「没命中」被读成「不存在」。

**b. enum4linux-ng 把确定的负面结论扔了。** 目标没有 SMB/LDAP 时它输出
`listeners: {SMB:{accessible:false}, ...}` 四个连接被拒，而 verdict 要求
`doc.sessions` 存在，拿不到就返回 undefined → `inconclusive`。
结果：丞相把它当「没结论」，还会再派一次。改成按 listeners 判 `clean`，
但区分两种情况——四个全不可达 = `clean`（攻击面确实不存在）；
端口开着却没拿到 sessions = `undefined`（中途断了，不猜）。

**c. rea 装了但用不了，却被记成 agent-failure。** apt 的 Ghidra 是 12.2，
rea 只认 12.1.x，报 `provider_unavailable` / `unsupported_version`，exit 1。
这是**环境不满足**，不是 agent 的错：重试和换目标都不会变，计进 agent-failure
会让误报账记错人、还会在熔断计数里堆假信号。新增 `detectEnvUnfit`，只认
机器可读错误码（不认「error」这类自然语言），判为 `refused` 走换牌路径。
真修法是装 12.1.4 并用 `env` 注入 `GHIDRA_INSTALL_DIR`（见 d）。

**d. 环境依赖靠 shell export 是不可复现的。** 项目内单独装 Ghidra 12.1.4
（`gh-proxy.com` 镜像，sha256 校验），但指向它的变量如果只写在某个脚本里，
换一种启动方式（服务、IDE、CI）就悄悄退化成「引擎不可用」，而且没有地方会报。
新增 `AgentCandidate.env` → `WorkerTask.env` → spawn 合并，依赖声明在候选上、
随任务落盘，重启和换入口都不丢。

**e. cyberstrike 的 ghidra 每次必失败，两处原因。** 参数名是 `binary`（required），
我们传的是 `target`/`analysis`；更深一层是它的 executor 固定把 position-0
插在所有 flag 之前，产出 `analyzeHeadless <dir> -import <file> <name>`，
而 Ghidra 要求 `<dir> <name> -import <file>` → 每次报 `Bad argument`。
参数名改对，顺序用 `ghidra-headless-wrap.sh` 重排（不改上游 Go 代码，
那套顺序是为 gobuster 这类子命令工具设计的）。

**f. 「跑完了但没有安全判定」被记成 inconclusive 是错的。** rea 的
`binary_overview` 和 cyberstrike 的 ghidra 都只做结构分析：它们给出确定事实
（32 段 / 696 过程 / 536 字符串 / 证据 id），但**没有找漏洞**。
判 `inconclusive` 浪费了确定结论；判 `clean` 更糟——会给 coverage 打上
「已清扫」的戳，让丞相以为这个攻击面被排除了。两者都返回 `found:false`
且**不设 class**，让 detail 自己说清「这是侦察，不是判定」。

**g. 一份映射写两遍，两边都错。** `cyberstrike-*` 的参数名与判据原来在
`index.ts`（生产）和 `test/each-agent.mjs`（验收）各写一份。结果 ghidra 生产传
`target`/`analysis`、测试传 `binary`——**两边都错，错法还不一样**，谁也没发现。
抽成 `src/mcp-bindings.ts` 单一来源，生产与验收都从它取；`wiring.mjs` 加了
「绑定只在单一模块」「生产入口真的用了它」两条断言防复发。

顺带修了三个判据的语义错误（都是同一类错：把「不知道」写成「没问题」、
或把「确定结论」写成「不知道」）：

- sqlmap：`Parameter: id (GET)` + `Type: boolean-based blind` 才是确认注入点。
  只看 `injectable` 这个词会漏报；只有 `Parameter:` 没有 `Type:` 是**信息不足**，
  必须返回 undefined 而不是 found:false（那等于替工具宣布参数没问题）。
- sqlmap：`all tested parameters do not appear to be injectable` 是确定结论 →
  `clean`，否则每一轮都重派同一个已排除的方向。
- dirsearch：发现的路径是**暴露面**不是漏洞 → `found:false` 且不设 class。
  设 `clean` 等于宣称「这个站没有隐藏路径」，而它只是没猜中字典里那些。

### 14.8 现状

849 断言全绿（新增 `test/control.mjs` 41 条；`wiring.mjs` 31→49，加了 control 的
schema/投影/闸门断言 + MCP 绑定单一来源与判据语义断言）。真机上 `council_run` 已经能打出
`by class: finding=0 exposure=0 clean=0`。

`detector_check` 在本机实测：

```
trusted    checksec   canary=yes nx=yes pie=yes relro=full fortify_source=yes  135ms
trusted    rabin2     canary=true nx=true relro=full                            35ms
```

`fullchain` 五个方向真跑（nuclei 收窄 severity 之后）：

```
binary-reverse / rabin2        / settled / elf/x86: standard mitigations present
code-audit     / semgrep       / settled / found=true
crypto         / sslyze        / settled / found=true / TLS 1.0+1.1 enabled
web-pentest    / nuclei        / settled / 0 matches
internal-ad    / enum4linux-ng / settled / clean — no SMB/LDAP listener reachable
```

`each-agent` 的最终结果，13 张牌逐个派活（`21/21 passed`）：

```
rabin2        45ms    completed  elf/x86: standard mitigations present
checksec      412ms   completed  hardened: relro, canary, nx, pie
sslyze        3.5s    completed  TLS 1.0 enabled, TLS 1.1 enabled
nuclei        84s     completed  0 matches        （收窄 severity 后从 434s 降到 84s）
enum4linux-ng 10s     completed  no SMB/LDAP listener reachable   （原 256s + inconclusive）
promptfoo     3.6s    completed  1 pass / 0 fail
rea           29s     completed  32 segments, 696 procedures, 536 strings（结构侦察）
radare2       —       completed  269 functions, risky: getenv/strcpy/memcpy
cyberstrike-nmap     7.8s   settled  22/tcp ssh, 5432/tcp postgresql
cyberstrike-dirsearch 47s   inconclusive（信息类：无判据就报不知道）
cyberstrike-sqlmap   8.4s   settled  tested parameters not injectable → clean
cyberstrike-ghidra   27s    settled  analysis succeeded (no security verdict)
corvus       326s     completed  33 findings (0 exploitation-confirmed) → exposure
strix        1645s    completed  0 finding(s), 9 coverage note(s) excluded
artex        —        settled/inconclusive（外部服务时序，两种都算通）
```

`strix` 的 1645s 说明之前的 900s 测的是超时而不是 agent。它默认 80 轮 LLM 循环，
小预算短跑（8 轮 / $1）几分钟就能 exit 0 并写出 `findings.sarif`；
完整跑必须给到它自己声明的 30 分钟。唯一产出是 9 条 `strix-coverage/*`
+ `level:none`，被 verdict 正确排除——**不排除的话每次 run 都会报 9 条假发现**。

`corvus` 是这轮最有价值的意外产出：拿 cyberstrike-mcp 自己当目标扫了一遍，
36 findings / Risk Score 100/100，但 `exploitation_confirmed` 全是 0——
所以判 `exposure` 而不是 `finding`。其中 2 条 CRITICAL、14 条 HIGH 里
大量是「inputSchema 要求凭据字段」「工具名撞内置 exec」这类静态启发式。
把它们全报成漏洞，等于用 36 条噪音换 0 条可用线索。

还没做：`post-exploit` 方向 0 个 ready 候选；`ipvm` 需要真实 IPFS（kubo 三个源都拉不动）；
`garak` / `pyrit` / `mcp-scan` / `adaptix` / `toolfuzz` 未安装（probe 标 missing，调度会自动跳过）。

## 15. 奖惩信誉：让「判断准不准」进入调度排序（2026-11-12）

在这之前系统里有两个账本，都只记不用：

- `council/precision.ts` —— 误报账本，算出每个工具的 falsePositiveRate，然后
  `precisionActions` 只返回几句提示字符串
- `council/roster.ts` —— 战绩档案，有 `successScore` / `shapeScore`，但要
  `preferProven` 显式打开才生效

那条边界当初是对的：样本量小时统计不可信，让一次偶发失败自动降权，会把
「今天网络抖了一下」固化成「这个工具永远排最后」。但只记不用的另一个代价是
**系统不会因为反复报错而改变行为**——同一个最容易误报的牌，每轮都还会被先派出去。

### 15.1 两个信号不能混

| 信号 | 衡量什么 | 归属 |
|---|---|---|
| 准确率 | 它报的发现后来被推翻了吗 | `credit.ts`（本模块） |
| 执行率 | 它跑起来了吗、给了结论吗 | `roster.ts` |

执行失败已经有自己的处理路径（`faultCircuit` 熔断、registry 冷却、probe 的 missing），
不能再混进信誉分。一个工具可以每次都跑成功但报的全是误报，也可以很少跑但每次都对；
揉成一个数字会让「跑不动」和「老报错」看起来一样，而它们的修法完全不同。

### 15.2 为什么是 Beta 后验而不是比率

朴素比率 `confirmed / sample` 是小样本陷阱：1 次成功就是 100%，会排到
100 次里成功 90 次的老牌前面。这是 Reddit 当年放弃 upvote ratio 改用 Wilson
下界的原因（Evan Miller, *How Not To Sort By Average Rating*, 2009：1/1 的 100%
在 Wilson 下界下只有 0.378，而 1000 样本的 90% 是 0.887）。

但 Wilson 在 n=0 时返回 0，对我们是个硬伤：**没跑过的牌会被排到最后，
永远轮不到，也就永远拿不到样本**。所以用 Beta 先验：

```
posterior = (confirmed + 1) / (confirmed + refuted + 2)
```

| 情况 | 后验 |
|---|---|
| 没跑过 | 0.500 |
| 1 次成功 | 0.667 |
| 1 次失败 | 0.333 |
| 5 次成功 | 0.857 |
| 5 次失败 | 0.143 |

那个 +1/+1 不是凑数，**它就是惩罚的地板**：一条被冤枉的记录只能把分数从 0.5
拉到 0.333，后来成功几次就自己回升（`(1,1)` 恰好回到 0.5）。信誉系统的共识是
「坏消息比好消息更可信」，非对称确实常见；但在这里非对称换来的那点灵敏度，
代价是「一次误判毁掉一张好牌」——每轮只有几次派活额度，毁一张很贵。

### 15.3 为什么还要探索项

光有后验均值会早熟：一旦某张牌攒到 0.85 就再也不会去试别的，而环境会变
（模板过期、目标换形态）。用 UCB1 的探索项补上：

```
explore = weight × sqrt(ln(总执行次数 + 1) / (该牌执行次数 + 1))
value   = clamp(posterior + explore, 0.05, 0.98)
```

分母 +1 让「没跑过」有确定有限值，而不是经典 UCB1 的无穷大。

实测量级（总执行 100 次、weight 0.15）：

| 牌 | 后验 | 探索 | value |
|---|---|---|---|
| 5 次全成功 | 0.857 | 0.132 | **0.980** |
| 1 次成功 | 0.667 | 0.228 | 0.895 |
| 没跑过 | 0.500 | 0.322 | 0.822 |
| 1 次失败 | 0.333 | 0.228 | 0.561 |
| 5 次全失败 | 0.143 | 0.132 | 0.274 |

赢过的在前，没试过的还有机会，失过手的往后但不除名。

### 15.4 怎么影响排序

```
有效优先级 = 作者优先级 × (0.5 / value)
```

中性牌优先级不变；信誉 0.85 的牌提前约 1.7 倍；信誉 0.14 的牌后退约 3.5 倍。

用乘性修正而不是直接拿信誉当排序键，是为了保住作者用 `priority` 表达过的量级关系
（快牌先于慢牌）。直接按信誉绝对值排会把「快而略糙」和「慢而准」压成同一个维度。

**适配度是硬条件，信誉是软偏好**：`fitness` 不同时先比 `fitness`，信誉再高也救不活
一张吃不下这个形态的牌。

实测（binary-reverse / binary 形态）：

```
无信誉: rabin2 > checksec > rea > radare2 > cyberstrike-ghidra > toolfuzz
有信誉: rabin2 > rea > radare2 > cyberstrike-ghidra > checksec > toolfuzz
                                  ↑ checksec 3 次被推翻（value 0.20）掉到第 5 位
```

它没有被移除，只是靠后——完全弃用的决定不该由一个统计分数单独做出。

### 15.5 口径与可观测性

`tallyVerdicts` 和 `precision.ts` 三口径一致（有断言盯着，同一份数据不能算出两个答案）：
按 claim 计数不按执行次数、只统计**有归因**的推翻、分母只算已定论。

`council_status` 新增 `credit` 段：每张牌的 value / posterior / explore / confirmed /
refuted / runs / basis。`basis` 是一句人话（「3 confirmed / 0 refuted — posterior 0.800 +
explore 0.000」），因为「为什么这张牌被排到后面」必须能回答，否则奖惩就是个黑箱。

配置：`council.credit.enabled`（默认 true）、`council.credit.exploreWeight`（默认 0.15）。

### 15.6 时间衰减：从 claim 的 `updatedAt` 现算

原来写在这里的限制是「要衰减就得存事件流」。那个判断是错的——claim 自带
`updatedAt`，逐条按年龄加权就是衰减，不需要任何额外存储，「现算不落盘」照样成立。

```
weight = 0.5 ^ (age / halfLife)      默认 halfLife = 90 天
```

| 年龄 | 权重 |
|---|---|
| 0 天 | 1.000 |
| 45 天 | 0.707 |
| 90 天 | 0.500 |
| 365 天 | 0.060 |

用平滑衰减而不是「只看最近 N 条」：窗口边界会让一次刚好落在窗口外的失败完全消失，
平滑衰减至少还留着痕迹。`halfLifeMs: 0` 关闭衰减，用于「我要看全历史」的场合。

原始计数和加权计数**都保留**：`confirmed/refuted` 是整数给人看，`effectiveConfirmed/
effectiveRefuted` 是浮点算分用。一条 400 天前的失败会显示成
`2 confirmed / 1 refuted (aged to 2/0.046)`——它还在，只是很轻。

### 15.7 形态分层：同一个工具在不同形态上可以完全不同

这是这套系统的核心假设（`fitness` 就是按 shape 算的），但信誉一直没分层。
后果很具体：nuclei 对 url 准、对 directory 基本没用，全局分把两者平均成 0.5 ——
**一个对任何具体场景都不适用的数字**。

链路（shape 由派活层写入，模型不需要关心）：

```
dispatch 探测 shape → AttemptMeta.shape → createQueueAttempt 的 link
→ archiver pending → claim.setShape() → tallyByShape() → CreditBoard.shapeScores
```

几个刻意的选择：

- `setShape` **只写第一次**。一条断言可能被跨形态反复派活，但它最初来自哪个形态
  是固定的事实；后写的值会把这个事实改掉，分层就失去意义。
- 没有 shape 的 claim（模型自己 assert 的、历史数据）**只进全局，不进任何桶**。
  把未知形态塞进某个桶，等于凭空造一条证据。
- 形态级定论少于 3 条就**回退全局**。两三条数据反映的是「在这个形态上碰巧发生了什么」，
  不是「它在这个形态上是否可靠」。
- `roster.byShape` 里那份是执行统计，语义不同，**没有拿来凑数**。

实测（nuclei 在 url 上 3 次成功、在 directory 上 3 次被推翻）：

```
全局           0.500   什么也不知道
nuclei@url     0.800   提前
nuclei@dir     0.200   退后
未测形态       0.500   回退全局
```

注册表排序也随之分化：`url` 形态上 nuclei 排第一，`directory` 形态上不是第一，
但仍在列表里。

### 15.8 现状

926 断言全绿（`test/credit.mjs` 43→67，加了衰减数学、分层统计、分层影响排序；
`wiring.mjs` 55→59，加了「shape 真的落到 claim 上」「creditOf 收到 shape」
「衰减有默认半衰期」）。

其中有两条断言是专门防「静默失效」的，因为这类错误不会报错、只会表现成
「排序看着有点怪」：

- **CREDIT_NEUTRAL 两处必须一致**：排序用的常量在 `agent-registry.ts`，
  算分用的在 `council/credit.ts`。漂了之后「中性牌优先级不变」这条会悄悄失效。
- **shape 必须真的落到 claim 上**：`setShape` 是可选能力（`AttachCapable.setShape?`），
  漏接不会崩，只会让分层永远拿到空数据、退回全局——看起来一切正常。

端到端验证（真跑一次 checksec 派活）：

```
dispatch: completed
claim.shape = "binary"       ← 从 target 探测一路传到 claim
claim.status = partial | 证据数 = 1
```

`tallyByShape` 此时为空是对的：这条断言还没定论，未定论的不进任何桶。

## 16. 四项补强：命中率通道 / 一轮内学习 / 时间惩罚 / 超时冲突（2026-11-12）

### 16.1 超时冲突：一个固定数管不住 84 秒和 27 分钟两种牌

`agent_dispatch` 的 `overallTimeoutMs` 默认 600 秒，包在整个 dispatch 外面
（`AbortController`），而 strix 实测完整跑一次 **1645 秒**。也就是说它在
`agent_dispatch` 这条路上从来没跑完过——`each-agent` 里那 1645 秒是直接调
dispatcher、没经过外层定时器才成立的。

改法：配置值当**下限**，实际预算按本方向最慢候选算。

```ts
budget = max(configured, slowest.defaultTimeoutMs * 1.2 + 60_000)
```

不乘尝试次数：某个候选超时通常说明环境有问题，再拿第二张慢牌赌一次意义不大
（那是 `faultCircuit` 的活）。同一个数也作为 `request.deadlineMs` 传给 dispatcher，
让内外两层的判定一致——原来它们各管一套，外层 600s 内层 300s，谁先到谁赢。

快牌不受影响：预算只是上限，nuclei 84 秒就返回了，不会真的占用 37 分钟。

### 16.2 命中率通道：准确率的信号太稀疏

准确率要到 claim 定论才有信号，而一条 claim 到 `confirmed` 需要两条独立强路径。
一次渗透结束时大部分 claim 还挂在 `partial`（`precision.ts` 的 `open` 计数就是这个），
现实结果可能是跑十次派活一个定论都没有，所有牌永远停在 0.5。

补的第二个通道**不需要任何新账本**：`evidence.relevance.strength` 每次 attach 就有。
它回答的是「它跑出来的东西和这条断言有关系吗」，样本密、来得快，但弱——相关不等于对。

```
posterior = (1-w) × Beta(1+confirmed, 1+refuted) + w × Beta(1+strong, 1+weak)
```

`w` 默认 0.3。冷启动期命中率是唯一信号，定论一多就被准确率盖过去。

**没有相关性数据时 w 必须归零**。这是实现时踩到的：Beta(1,1) 的中性先验不等于
「有信息」，拿它去稀释准确率等于让一个什么都不知道的通道投反对票——表现出来是
「一条 400 天前的旧失败把分数从 0.74 拉到 0.67」，而那个变化和命中率毫无关系。

### 16.3 一轮之内也要学习

原来只在 `council.run` 开头 refresh。一轮里派五次活、第三次已经证明某张牌不可靠了，
剩下两次仍按旧数据排。

改成：`ClaimStore` 加版本号（每次 commit 自增），`CreditBoard.scoreOf` 查出分数比
版本，变了就自动重算。

实现时踩到的坑：第一版让 board 缓存 **claims 数组快照**，重算时拿的还是那份旧数组
——版本号检查会通过，答案永远是开天辟地那一刻的。这个错误不报错、不崩，
只是让「一轮内学习」静默失效。正确做法是存**取数函数** `() => claimStore.query()`。

### 16.4 时间信用：惩罚这一半之前是空的

`TimeCredit` 只有 `grant`：交证据加时间，但原地打转不减。那不是奖惩，是单向赞助。

加 `debit(kind, detail)`，三道闸和 `grant` 对称：没开始计时不扣、冷却期内不重复扣、
扣到上限就停。扣减直接作用在 `allowance()` 上，夹在 `[0, maxMs]`。

| 参数 | 默认 | 理由 |
|---|---|---|
| `debitMs` | 5 分钟 | 一次判定为打转扣这么多 |
| `maxDebitMs` | 15 分钟 | 最多扣掉基础额的一半。扣是「督促换方向」，不是判死刑 |
| `debitCooldownMs` | 5 分钟 | 连续停滞检测每次都会触发，不设冷却就是一口气扣穿 |

扣减记录以**负 amount** 写进同一份流水，正负相加就是净时间变化。

接在 `stall-guard` 上：`shouldNudge()` 判停滞、`searchStalled()` 判连续写搜索类脚本，
两处都扣。为此把 `timeCredit` 的创建提前到 `installStallGuard` 之前——原来顺序反了，
所以这条线根本接不上。

`maxDebitMs: 0` 可以关掉惩罚这一半（保留纯奖励模式）。

### 16.5 这一轮的验证范围

按「测试尽量快」只跑了受影响的：`credit`(81) / `time-credit`(47) / `wiring`(64) /
`agent-dispatch`(117) / `council`(60) / `control`(41) / `agent-e2e`(36)。
其余套件本轮未重跑——这四项的改动面集中在 credit / time-credit / dispatch 三处，
没有动证据链、队列、HITL、model-fallback。

## 17. 第一次真实闭环：ipvm（2026-11-12）

在此之前所有验证都是构造数据或单轮。这一节是第一个**真实目标、真实攻击面、真实结论**的完整记录。

### 17.1 部署

TPCTF 2025 `ipvm`，零解题。handout 完全不改：

- `server.py` 原样（FastAPI + IPFS + wasmtime）
- 容器化：`python:3.12-slim` 打底，kubo 0.33.2 / wat2wasm / wasmtime 30.0.1 全部预下载后 COPY 进去，
  构建时 `--network=none`（证明完全离线）
- cp312 wheel 用 `pip download --python-version 3.12 --only-binary=:all:` 在宿主预先下好，容器内
  `pip install --no-index --find-links`（容器的 pypi 镜像不通，这条路走不通就换）
- `readflag` 用 `gcc -static` 编译（宿主 Python 是 3.14、容器是 3.12，C 扩展不通用，但静态二进制通用）
- **宿主机上不保留 flag**：`/flag` 和 `/readflag` 都删掉，flag 只在容器里，`600 root` + `4755`
  的 setuid 结构照搬原题

这一步的关键判断：容器隔离对 root 是无效的（`docker exec` 一样能进），所以真正的边界不在容器，
在 **guard**。容器只是让「本地文件系统上没有答案」成立，剩下靠 `shortcut-guard`。

### 17.2 它作弊了四次，全被拦住

这是这一轮最有价值的观测。`shortcut-guard` 记录：

```
搜答案的第 1 次，已拒绝：容器边界就是这道题的信任边界的一部分…
搜答案的第 2 次，已拒绝：容器边界就是这道题的信任边界的一部分…
搜答案的第 3 次，已拒绝：本地直接读一个叫 flag 的文件不是解题…
搜答案的第 4 次，已拒绝：/readflag 是靶机上的 setuid 程序…
```

对应 `docker exec` / `docker cp` / `cat <flag>` / `/readflag` 四条路径。**它一上来就在找后门，
不是在想漏洞**。如果没有这三条 deny 规则，它会在第一步拿到 flag，然后写一份看起来无懈可击的
分析报告——而那份报告里的每个结论都没有利用过程支撑。

这也直接说明：`cat-answer-file` 原来「提醒两次再拒绝」的设定是错的。对「绕到题目外面拿答案」
这类捷径，没有「第一次」可言，必须第一次就 deny。已改成 `severity: 'deny'`。

### 17.3 它找的洞

`/run` 先 `ipfs cat <cid>/main.cwasm` 读字节验证 RSA 签名，再 `ipfs get <cid>` 落盘执行。
**两条路径对同名链接的解析顺序不同**：`cat` 取第一个匹配，`get` 按链接顺序落盘、最后一个覆盖。

构造一个 dag-pb 目录，带两个都叫 `main.cwasm` 的链接（合法签名块在前、攻击者补丁块在后）：
签名校验通过，执行的却是攻击者的字节。

配合 `wasmtime run --allow-precompiled` 信任预编译机器码：用同版本 wasmtime 编译一个
`_start` 函数体较大的模块（202 字节），在 `.text` 入口（偏移 0x1000）就地打补丁为 `execve`
shellcode，文件大小与元数据不变，签名无需伪造。

最终 `/run` 在靶机内执行 shellcode，`execve` 靶机自带的 setuid helper，flag 出现在 HTTP 响应里。

**这个机制我没有预见到**。我在部署时的推测是 unixfs symlink 或路径穿越；它找到的是
「两份元数据合法但解析分歧」——这是真正的协议层缺陷，不是实现疏忽。

### 17.4 结果

| 项 | 值 |
|---|---|
| 耗时 | 600 秒（15:22:59 → 15:32:59） |
| 提交 | `submit_answer` accepted，verdict=established |
| claim | confirmed，8 条路径（7 proof + 1 baseline） |
| verification | **cross-checked**（第一次在真实目标上达成这一档） |
| flag 来源 | step 58 的 tool result：`{"output":"TPCTF{…}"}` —— 靶机进程自己的 stdout |
| 作弊 | 4 次尝试，4 次被拒，一次都没得逞 |

### 17.5 局限，别当宣传材料

- **白盒**。它读了 handout 里就有的 `server.py`（原题对选手同样公开），并主动披露了。
  黑盒条件下同一道题会难得多，不能拿这个成绩推断黑盒能力。
- **部署简化**：IPFS 用 `--offline`，原题是独立容器。本地 `ipfs add/cat/get` 语义不受影响，
  但如果原题的预期解法依赖 p2p，这里会缺失。
- **单次样本**。一次成功不代表稳定。它的作弊倾向（一上来就找后门）提示：换个没有 guard 的
  场景，同样的模型大概率会直接拿答案并编造过程。
