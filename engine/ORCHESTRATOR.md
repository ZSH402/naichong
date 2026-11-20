# 奶虫 · 编排器（orchestrator.py）

解决的是**主控自身缺的四样东西**。它们都不是知识问题——今天的证据说明模型够聪明，
缺的是脚手架。靠提示词让模型自觉，历史证明无效，所以全部落成代码。

## 一、时钟注入

每轮 prompt 开头强制带上：现在是几点、本题还剩几分钟、截止几点。

为什么会需要：实跑中它开赛五分钟了还以为没开赛，自己 `sleep` 到"02:00:10"而实际已经
02:05。没有外部时钟，模型的"时间感"完全来自它读到的最后一句话。

## 二、单题 deadline

`--deadline-min`（默认 45）。到点编排器直接退出，不再开新一轮。

为什么会需要：5 小时的比赛里，一题卡过 45 分钟就该让位。之前没有这个约束，
它会在一道题上耗到比赛结束。

## 三、进展心跳 + 上下文压缩

每轮结束必须写 `ROUND.md`，编排器解析后只把**结论摘要**塞进下一轮 prompt，
原始日志留在文件里不进上下文。

- 判据保守：`ROUND.md` 里有实质结论或新假设才算"有进展"，"我又想了想"不算
- 实测上下文曾涨到 834KB，一轮调用要几分钟；只带摘要后每轮回到正常量级

## 四、两阶段假设：先收敛，卡住则大胆猜测并快速证伪

这是核心。状态机：

```
converge ──(连续 2 轮无进展)──▶ guess
   ▲                              │
   └──(任一假设被确认/拿到新证据)──┘
```

**converge 阶段**的硬要求不是"多想想"，而是：每条走不通的路必须写进
`ROUND.md` 的「排除了什么」并给一句话依据，下一轮不许再回去。

**guess 阶段**的硬要求：提出 ≥2 条新假设，每条带「什么观测能证明它错」，
然后**先打最快能被证伪的那条**。猜测的价值在于快速否定，不在于一次猜对。

### 实测效果对比

比赛时（无编排器）它对这个 reverse 题的判断是：

> 这是编译进 TrueType 的逻辑电路，逆向很复杂，**ROI 低，跳过**。

换成编排器后第 1–2 轮的 `ROUND.md`：

> 24 个 hex digit 被存成 24 个 `digit<<16` 的 16.16 坐标，block0 取第 0..15 个、
> block1 取第 8..23 个；实测 0、0123…、ffff… 三组输入两段 marker 都恒为 128，
> 说明输入目前根本没有影响 hint 结果——这是本轮新卡点。
>
> 排除了什么：输入解析/坐标打包是卡点（依据 `objdump` 0x1148–0x1187）……
> 新假设 H3：输入坐标被夹到轴范围，16 个 nibble 实际全同，怎么证伪……
> 新假设 H4：hint 程序没有真正执行，marker=128 是未 hint 的原始轮廓，怎么证伪……

差别不在模型变聪明了，在于「必须写出排除了什么」和「卡住必须提可证伪假设」
这两条被强制了。

## 五、单轮墙钟上限（300 秒）

轮间重置治不了**轮内**上下文膨胀，时钟注入也只在轮首有效。所以单轮有实际耗时上限：
到点按**进程组**整组 SIGTERM，15 秒后 SIGKILL。

用 `Popen + preexec_fn=os.setsid` 而不是 `subprocess.run(timeout=)`——后者只杀直接子进程，
而这里隔了 `su` 和 `run.sh` 两层，真正的 node 是孙进程，会活下来继续占 CPU。

超时也照样读 `ROUND.md`：它往往已经写下本轮结论，只是没收尾。状态里记 `last_timed_out`，
下一轮 prompt 会当面提示「上轮超时收束，本轮先做最小可验证的一步」。

## 六、假设质量校验

「必须提可证伪假设」不能只靠格式。`MIN_FALSIFY_LEN = 8`，证伪条件写「未写」「待定」
「需要进一步分析」的一律标 `quality: low` 并累计计数。累计到 3 条，下一轮 prompt 直接点名：
本轮的假设必须给出**一次请求或一次本地实验就能否定**的具体观测。

不丢弃低质量假设——丢弃只会让模型干脆不写，写出来并计数才能施压。

## 七、裸提交检测

幂等只活在 `ctfy.py` 里，裸 `curl`/`requests` 打 `/submissions` 会绕开台账。
每轮结束后扫日志和 workspace 里的脚本，命中就记进 `raw_submit_hits`，
下一轮 prompt 明确警告「提交必须走 ctfy.py」。

只检测不回灌拦截：网络层拦截的代价大于收益。实测三种情形判得准——
日志里的裸 curl 检出、脚本里的 `requests.post` 检出、正常走 `ctfy.py` 不误报。

## 用法

```bash
# 单题
python3 /root/tpctf/orchestrator.py --challenge AUTHORED-xxx --deadline-min 45

# 多个离线题（fanout 已自动走编排器）
DEADLINE_MIN=45 ./fanout.sh AUTHORED-aaa AUTHORED-bbb
```

状态与产物：

```
/root/tpctf/orchestrator/<challenge>.json          阶段/轮次/假设库/截止
/root/tpctf/orchestrator/<challenge>-prompt-rN.md  每轮实际注入的 prompt
/root/tpctf/orchestrator/<challenge>-rN.log        每轮完整日志
/root/proj/workspace/orch-<challenge>-rN-*/ROUND.md  每轮结论
```

假设库在 `<challenge>.json` 里累积，跨轮次保留 —— 所以「已排除的方向」不会被
下一轮重新捡回来，这是防打转的关键。


## 八、上下文膨胀的三个解法（按 Anthropic 官方实践）

参考 [Effective context engineering for AI agents](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)：

**context rot 是结构性的**——O(n²) 的 pairwise attention 意味着上下文越长召回越差，
窗口再大也逃不掉。所以方向不是"压缩得更狠"，而是**不让内容进来**。

### 1. 材料索引（just-in-time retrieval）

附件只给「路径 + 字节数 + 是否需要切片」，**不内联内容**。
实测：`challenge.ttf` 758KB，索引占 **111 字符**。

同时给大文件打标记：「不要整读，用 head/grep/file 取片段，或派 subagent」——
这正是 Anthropic 说的 progressive disclosure：文件元数据本身就是低成本线索。

### 2. Sub-agent 隔离（最强的破局手段）

官方给出的比例：subagent 可以消耗几万 token 探索，**只回传 1–2K token 的浓缩摘要**。
所以任务书里明确要求「大文件/长输出不要直接读，派 subagent 或只读片段」。

### 3. 单轮墙钟（已有，见第五节）

300 秒到点按进程组整组杀。这是兜底——它不能阻止轮内膨胀，只能限制膨胀的**上限**。

## 九、判断质量的解法：裁决闭环

之前只强制「提出可证伪假设」，缺了 Reflexion 最关键的那一环：**回来对照观测判真假**。
现在 `ROUND.md` 多了强制段落：

```
## 上轮假设的裁决
- H1：实际观测=改轴0后16个输出全变  判定=refuted
- H2：实际观测=marker恒为128不随输入变  判定=confirmed
```

编排器解析后写回假设库状态：

- `confirmed` → 进「已确认的结论」，下一轮不许重复验证
- `refuted` → 进「已排除的方向」，下一轮不许回去
- `inconclusive` → 保持 open

且「有裁决」本身算进展——**把一条假设判死，比再提三条新的更有价值**。

这条闭合之后，假设才真正是"假设-实验-判定"的循环，而不是"提完就忘"。

### 实测（真跑产出，非示例）

第 3 轮的 `ROUND.md` 里它写的是：

```
- H1：实际观测=`/tmp/explore` 单轴扫描（j=0..15）时 L0 输出有 7~16 个坐标
      同时变化，不是逐坐标可分  判定=refuted（"逐级单轴/差分恢复矩阵"不成立）。
- H2：实际观测=`I.asm` 只有 25 条真实指令…点 66 从 subleq VM 的 storage[75] 取
      判定=inconclusive：机制 confirmed，但"16 元素硬编码目标向量可直读"被 refuted。
- H3：实际观测=fpgm 表 84 字节，反汇编为 function 0（subleq）…  判定=confirmed。
```

回填结果：H1→`refuted`、H3→`confirmed`（各带观测证据）、H2 因 `inconclusive`
保持 `open`——没定论就不该死，这个语义是刻意保留的。

抓到一个静默失效的 bug：判定值后面跟着中文括号解释（`判定=refuted（…）。`），
原先整串比对，全部落空后被默认改写成 `inconclusive`，回填条件永不成立、
裁决闭环**没有任何报错地失效了**。改成只提取 `confirmed|refuted|inconclusive`
关键词后正常。这类"写了但不生效"比直接报错危险得多。


## 十、领域规格（专业化）

写在 `/root/tpctf/agents/<domain>.md`，六份：`web` / `reverse` / `pwn` / `crypto` / `misc` / `ai-security`。

每份不是"你是某领域专家"这种空话，是四段可执行内容：

- **假设模板**：按顺序走的攻击路径（写顺序，不是罗列——它决定了先试什么）
- **失败模式**：这领域最常见的误判，全部来自实测踩过的坑
- **验证纪律**：什么算证实（Body-Diff、对照组、可重放、唯一性）
- **工具子集**：该领域该用哪些，以及哪些有坑（如 `RsaCtfTool` 不能用 `--attack all`）

编排器按 `--domain` 加载，注入到每轮 prompt 最前面（是角色，不是参考资料）。
prompt 从 1010 字符涨到 2579 字符，增量 1.5K。未知方向返回空，安全降级。

### 实测效果（同一个 reverse 题，带规格 vs 不带）

不带规格时它逆到地址级就停在"未解出"。

带规格后一轮产出：

- **排除了 7 条路，每条带实测依据**：`gvar` 的 19 字形×24 tuple delta 全 `(0,0)` 是纯 decoy；
  用 `FT_LOAD_NO_HINTING` 对照证明 hinting 真在执行；24 轴逐一扫 0..15、
  两轴 256 组合、随机 3000 组，marker 恒 128；实测 `F(1,1) ≠ F(1,0)⊕F(0,1)⊕F(0,0)`
  逐坐标不符所以不是 GF(2) 线性；`HINT_PEDANTIC` 复核排除；name table 排除；
  最终字形 30858B 程序对 68 个点坐标零改变，排除"反汇编能读到写法"
- **提出可验证假设**：字形程序是寄存器 VM，`GETVARIATION` 取 24 轴存 `storage[1620..1643]`，
  跑 10241 次 `CALL 0` 调 `fpgm` 的 84B 解释器，末尾 `RS storage[75] → SCFS points[66].y`。
  证伪方法：把末尾 `RS 75` 改成 `RS k` 做寄存器读出探针
- **给出解法方向**：block0 用 in[0..15]、block1 用 in[8..23]、交集 in[8..15]，
  可做 meet-in-middle

差别不在模型变聪明，在于规格里那三条失败模式被真正执行了：
"换输入看结果变不变"变成 24 轴扫描加 3000 组随机；"hinting 有没有跑"变成 NO_HINTING 对照；
"是不是线性"变成逐坐标验算。

## 十一、并发扇出带方向

```bash
# 逐题指定（批内可混排）
./fanout.sh AUTHORED-37DA5EFD:reverse AUTHORED-CDB35578:misc

# 全局指定
./fanout.sh --domain web AUTHORED-13C7AF74 AUTHORED-xxx

# 不写方向也能跑，只是没有领域规格
./fanout.sh AUTHORED-xxx
```

每个 worker 都是编排器实例，独立 workspace、独立假设库、独立 deadline。

---

## 五、数据契约层（models.py，Pydantic v2）

### 为什么加这一层

原来的状态是裸 `dict`，在层与层之间无约束流动。代价在实战里出现过两次：

1. **裁决静默丢失**。模型把裁决写成 `判定=refuted（…）`（中文括号），旧代码拿整串比对
   `{"confirmed","refuted","inconclusive"}`，全部落空——但**不报错**，裁决闭环停摆好几轮，
   日志上只显示"本轮无进展"。
2. **格式错误被当成没进展**。ROUND.md 少个字段，靠手写 45 行 `if/else` 事后检测，
   检测结果记进 `format_errors`，但那一轮的假设与结论仍按"无产出"处理。

根子是同一个：**校验发生在消费时刻，而不是写入时刻**。

### 设计依据（业界共同做法）

- **状态 schema 是代码里的一等公民**。LangGraph 用 `TypedDict` + reducer 定义 state 形状，
  Pydantic 生态用 `BaseModel`；共同点是不靠隐式约定。
- **契约带版本号**。`schema_version` 作锚点：加字段天然兼容（`extra="allow"`），
  删改语义才需要迁移；读到的版本高于本代码时**明确拒绝**，而不是猜着读。
- **序列化边界统一**。落盘一律 `model_dump(mode="json")`，杜绝 datetime/自定义对象漏进磁盘。

### 落地形态

| 模型 | 职责 | 关键约束 |
|---|---|---|
| `Verdict` | 一条裁决 | `frozen=True`；`observation` 非空（没有观测就没有裁决）；`verdict` 在入口归一（`refuted（…）`/`REFUTED`/`已证伪` 都能进） |
| `Excluded` | 一条被排除的路径 | `frozen=True`；下一轮不许再走 |
| `Hypothesis` | 可证伪命题 | `falsify_by` 走占位词过滤，敷衍的降级为 `quality=low` |
| `RoundResult` | ROUND.md 的 JSON 块 | `assess()` 返回问题清单而非抛异常——一轮被砍在写文件中间是常态，整轮判废会丢掉已成立的结论 |
| `StateView` | 持久化状态 | `validate_assignment=True`；对调用点暴露 `st["x"]` / `st.get()`，**零侵入**但赋值当场校验 |

`StateView` 的 dict 兼容层是刻意的：orchestrator.py 里有 76 处 `st[...]` 和 17 处 `st.get(...)`，
全部重写的风险大于收益。兼容层只保证"赋值必须过校验"，不改变调用形状。

### 效果

`orchestrator.py` 从 775 行降到 709 行，`validate_round()`、`ROUND_SCHEMA_KEYS`、
`VALID_VERDICTS` 全部删除，职责移交给模型定义。

端到端验证（脏输入）：

```
{"id":"H1","observation":"...","verdict":"refuted（不是 atteset 入口）"}
{"id":"H2","observation":"...","verdict":"CONFIRMED。"}
→ [{'id':'H1','verdict':'refuted'}, {'id':'H2','verdict':'confirmed'}]   # 两条都保住
```

旧代码下这两条会**全部丢失**且不报错。

---

## 六、跨轮记忆与停滞检测（借 Archon 的架构）

参考对象是北大的 [Archon](https://ar5iv.labs.arxiv.org/html/2604.03789)（Rethlas 框架的 Lean 形式化 agent）。
它的三个观察和编排器实测到的病一一对应：

| Archon 的观察 | 编排器的对应病症 |
|---|---|
| 「agent 自己的失败尝试和悲观注释会侵蚀其坚持意愿」 | 每轮 salvage 出来的日志尾巴全是失败记录，下一轮读到就丧气 |
| 「规模变大后 agent 会忘记之前的尝试、反复走同一条死路」 | 排除过的路径解析完就丢，每轮从零开始排除 |
| 「stall 只在连续多个会话上才表现为模式」 | 每轮只看单轮快照，没人看趋势 |

### 6.1 MEMORY.md（跨会话记忆文档）

每轮结束写进 workspace，内容只有三类：**已确认 / 已排除 / 悬而未决**。
设计上刻意不放原始日志——Archon 的经验是"agent 只加载与当前任务相关的材料，
避免被无关信息干扰"，而原始日志正是污染源。

关键修复：`excluded`（已排除路径）以前只活在单轮 ROUND.md 里、`parse_round` 解析完就丢，
**跨轮从不累积**。现在按 `path` 去重accumulate进 state，并在 prompt 里单列一段：

```
## 已排除的路径（不要回头）
- /api/users/1 越权读他人资料 —— 依据：返回 403，且换 teamId 仍 403
- 从 page cache 捞 flag —— 依据：init 注释声明不落 cache

回到这些路径上等于承认上一轮的结论是错的；如果你确实要回头，先给出推翻原依据的新观测。
```

### 6.2 规则化停滞检测（check_stall）

Archon 用 Review Agent 做这件事，但那是因为它跑 80 小时、一次判定摊薄到可忽略。
编排器一轮 15 分钟，为"我们是不是卡住了"再付一次模型调用不划算。
所以用**跨轮累积量**判，不花钱：

| 判据 | 对应的失败形态 |
|---|---|
| 连续 N 轮无进展 | 最直接的停滞 |
| 高比例轮次靠日志回捞 | agent 从不写 ROUND.md，跨轮记忆一直断着 |
| 切过阶段却零裁决 | 换方向也没用 |
| 悬空假设 ≥5 条 | 用"提假设"冒充进展 |

命中 ≥2 条即判停滞，自动切 `guess` 阶段，并把理由注入下一轮 prompt 当面点出：

```
⚠️ 检测到停滞，上一轮结束时命中以下判据：
  - 连续 3 轮没有进展（要有新假设或新裁决才算）
  - 3 轮里有 3 轮靠日志回捞（说明每轮都没写出 ROUND.md，跨轮记忆是断的）

本轮不许沿旧路推进。要么给出一个能一次否掉当前主线的新观测，
要么明确写出「这条主线已死，理由 X」，然后换一条完全不同的路径。
```

### 6.3 没做的部分：Plan/Lean 双 agent

Archon 用双 agent（Plan 在新上下文规划、Lean 在受限范围执行）对抗上下文污染。
编排器**每轮本来就是新进程**，上下文天然干净，这个收益不存在，
所以没抄——只抄了对当前对症的两项。等单轮时长放大到数小时级别再看要不要分。

---

## 七、策略层（OPA / Rego）

### 为什么把范围闸从 Python 里挪出来

有一次为了绕开自己的范围闸，直接把 `allowedHosts` / `deniedTools` 清空了。
在 CTF 靶机上这只是权宜，在真实渗透里等于拆掉授权边界。

真正的毛病不在"清空"这个动作，在于闸的口径散落在 Python 的 `if` 里：

- 改起来太容易，且没有评审痕迹
- 无法单独测试——要验证"外网 IP 会被拒"，得把整个系统跑起来
- 无法向客户证明——"你怎么保证没打到范围外"的答案只能是"我们很小心"

挪到 Rego 之后有三个性质：**可单测**（15 条断言，`opa test` 秒级）、**可审计**（策略文件加测试就是证据）、**默认拒绝**（`default allow := false`，漏配等于拒绝）。

### 三个踩过的坑（都记在代码注释里）

**1. 策略读 `data` 会递归。** 第一版写 `object.get(data, "scope", {})`，报 `rego_recursion_error`。因为 `data` 是整棵树，测试包 `data.nai.scope_test` 也在里面，测试又调用策略，成环。
**解法**：范围从 `input.scope` 传入，策略变成无状态纯函数。同一份策略配不同 scope 就能服务不同 engagement。

**2. 放行路径静默失效。** `reason` 只在拒绝分支有定义，而 `decision` 无条件引用它 → 允许时 `decision` 整体求值为 `{}`。表现是拒绝用例全过、放行用例全挂，很误导。
**解法**：`default reason := ""`。

**3. complete rule 冲突。** 空 scope 时「未配置范围」和「未命中规则」两条 `reason` 同时成立，Rego 报 conflict。
**解法**：后者加 `count(...) > 0` 条件，与前者互斥。

### 结构

```
policy/scope.rego       策略（默认拒绝、三条放行规则、拒绝理由可读）
policy/scope_test.rego  15 条断言（含"子域不等同父域授权"这类边界）
scopegate.py            Python 侧：组 input → 调 opa → 翻译成人话
scope/example.json      范围数据样例
```

### fail-closed

`scopegate.check()` 永远返回 `Decision`，不抛异常。OPA 不存在、崩溃、超时、输出看不懂——一律 `allow=False` 且 `trusted=False`。

一个"闸坏了所以全放行"的实现比没有闸更危险，因为它给人虚假的安全感。

### 与 prompt 的一致性

范围配置同时进两处：Rego 闸判定 + 每轮 prompt 的开头。

```markdown
## 授权范围（越界即违规，不是尽量避开）
- 允许的网段：10.0.0.0/8, 192.168.56.0/24
- 允许的工具：nmap, ffuf, curl, nuclei

**范围外的一切资产都不在授权内。** 需要碰范围外的东西时，
停下来写清楚「为什么必须碰、属于哪个授权依据」，而不是先做了再说。
```

同一份 `scope.json` 驱动两边，所以不会出现"prompt 说可以、闸说不可以"的分歧。

### 没做的：Rust 执行层

进程/资源管理那块（`pkill -f` 自匹配、QEMU 打爆内存）确实该下沉到系统语言，
但那是**重构**，成本最高。当前证据更像是"我并发开太多"，不是缺少系统级原语。
等它成为常态瓶颈再说。

---

## 八、数据查询层（DuckDB）

### 缺的是什么

在这之前，一次作业的产物散在文件系统里：nmap 的 XML、httpx 的 JSONL、ffuf 的 JSON、
每个动作落盘的证据目录。要回答「这个网段还有哪些没打穿」，只能现写 Python 或者 grep 一堆文件。

更关键的是 **agent 看不到全局**——它只看得到本轮材料，不知道整个作业已经发现了什么、
还有哪些资产完全没碰。这个缺口现在由 prompt 里的「资产概况」补。

### 业界做法（两个共识）

参考 [DuckDB for Security Engineers](https://jaredgore.com/blog/duckdb-intro/)：

**1. 不建表导入，用 VIEW 直接映射文件。** 扫描产物持续产生，每次导入一遍（ETL）本身就是负担。
DuckDB 能直接 `read_json_auto('xxx.jsonl')`，数据落盘即可查。

**2. 字段标准化再 JOIN。** 不同工具对同一概念叫法不同，用 VIEW 映射到统一列名，
之后所有查询都打在统一视图上。

文中的一个数据点：10 万条 findings，DuckDB 约 2 秒，等价 Python 脚本 20 秒以上。
差别不在快，在于**查询是交互式的**——可以边看边改，而写脚本每次都要重跑。

### 分工

- **Python 负责解析**：nmap XML / httpx JSONL / ffuf JSON 的格式差异在解析层吃掉
- **DuckDB 负责查询**：只读规范化后的 JSONL，SQL 随意切

规范化落盘用 **append-only JSONL**，符合证据不可改写的性质；同一 `asset_id`
重复出现是允许的，后写的代表更新的观测。

### 四个模型

| 模型 | 关键字段 | 说明 |
|---|---|---|
| `Asset` | `asset_id`, `kind`, `host`, `port`, `service` | `asset_id` 稳定（`ip:port` 或 URL），findings 挂在它上面 |
| `Finding` | `asset_id`, `severity`, `status` | severity 用词与业界一致（critical/high/medium/low/info） |
| `Evidence` | `evidence_id`, `command`, `stdout_path` | 只追加不覆盖 |
| `Edge` | `src`, `dst`, `trusts` | `trusts` 描述下游信任上游的什么——这是攻击链核心，不是「有连接」 |

### 三个开箱查询

```sql
-- 还没打的地方（有资产但零发现）
SELECT a.asset_id FROM assets a LEFT JOIN findings f ON f.asset_id = a.asset_id
WHERE f.asset_id IS NULL GROUP BY a.asset_id

-- 攻击链：边表上的递归传递闭包
WITH RECURSIVE chain(src,dst,depth,path) AS (
  SELECT src,dst,1,[src,dst] FROM edges
  UNION ALL SELECT c.src,e.dst,c.depth+1,list_append(c.path,e.dst)
  FROM chain c JOIN edges e ON e.src=c.dst
  WHERE c.depth<5 AND NOT list_contains(c.path,e.dst))
SELECT * FROM chain ORDER BY depth DESC
```

递归 CTE 里踩了一个坑：`c.path || e.dst` 在 DuckDB 里对 `VARCHAR[]` 和 `VARCHAR`
不做隐式转换，必须用 `list_append()`。

### CLI

```bash
python3 store.py --root findings --ingest nmap scan.xml --ingest httpx http.jsonl
python3 store.py --root findings --untested        # 还没碰的资产
python3 store.py --root findings --chains          # 攻击链
python3 store.py --root findings --query "SELECT ..."
```

### 与编排器的连接

`--store-root` 配置后，每轮 prompt 注入：

```markdown
## 资产概况（来自扫描产物库）
- 资产 8 个 · 发现 2 条 · 证据 1 条 · 关系 2 条
- **完全没碰过的资产 7 个**：
  - 10.0.0.9:3389（port）
  - http://10.0.0.5/.git/config（url）

优先考虑这些空白点，而不是回到已有发现上做增量。
```

库不可用时静默跳过——这是辅助视图，不该阻断解题。

---

## 九、攻击路径图（Kùzu）

### 为什么在 DuckDB 之上还要一层图

DuckDB 用递归 CTE 也能算传递闭包，但两类问题它做不了：

**枢纽分析**——哪些资产被最多攻击路径穿过？这种"逐节点聚合路径"在 SQL 里要窗口函数叠递归，在图里是一句 group by。

**最短路径剪枝**——SQL 的递归 CTE 会把所有 ≤N 跳路径全物化再排序，深一跳就是指数增长；图库的 `* SHORTEST` 做 BFS，只出一条。

两者不是替代关系：**聚合统计归 DuckDB，路径推理归图**。数据只有一份（JSONL），两边都读它。

### 业界参考

- **Prowler 的 Attack Paths**：基于 Cartography 的通用图 schema，把查询模式化（提权子模式、网络暴露模式），并专门警告要**避免笛卡尔积**。
- **BloodHound**：AD 攻击路径的事实标准。抄的是它的核心表达——**路径是边的序列，每条边带「信任了什么」**。

### Graph schema

```cypher
asset(asset_id, kind, host, port, service, title)      -- 节点
finding(finding_id, title, severity, status)           -- 节点
affects(FROM finding TO asset)                         -- 发现落在哪个资产
pivots(FROM asset TO asset, trusts, kind)              -- 资产间跳转
```

`pivots.trusts` 是核心字段：下游信任了上游的**什么**（凭据、令牌、配置、网络位置）。没有 trusts 的边等于"可能相关"，在报告里说服力很弱。

### 五个查询

| 方法 | 回答什么 | 相对 SQL 的增量 |
|---|---|---|
| `reachable_from(entry)` | 从入口能到哪儿 | 递归 CTE 也能做 |
| `shortest_path(a,b)` | 两点之间最快怎么走 | **BFS 剪枝**，不物化全路径 |
| `chokepoints()` | 哪些节点是必经之路 | **逐节点聚合路径**，SQL 要窗口函数叠递归 |
| `isolated_assets()` | 扫到了但完全没碰的 | 三向 NOT EXISTS |
| `paths_to_severity(s)` | 几步能摸到 critical | 路径 + finding 混合查询 |

### 踩过的三个坑

**Kùzu 0.11 的 `Database(path)` 落盘是单个文件，不是目录。** 早先用 `os.path.isdir` 判断"是否已建库"，永远为 False，于是每次查询都触发全量重建，第二次撞主键。

**Kùzu 不支持 Neo4j 的 `shortestPath()`**，要用它自己的 `[:pivots* SHORTEST 1..5]`。三种写法实测：`* SHORTEST` 首选，`ORDER BY length(p) LIMIT 1` 可用但全物化。

**静默丢边。** `MATCH...CREATE` 匹配不到端点就安静地不建边——图上少一条路，人却以为"没有这条路"。现在建图前先查端点存在性，缺失的记进 `last_skipped` 一并返回：

```
跳过: [{'edge': 'http://10.0.0.5/->10.0.0.5/typo', 'why': "端点不存在: ['10.0.0.5/typo']"}]
```

### 三层标识（已修复的局限）

**问题**：实测发现 `10.0.0.5:80`（端口资产）和 `http://10.0.0.5/`（URL 资产）**是同一个东西**，
但 `asset_id` 拼法不同，在图上成了两个互不相连的节点。后果是端口类资产全部显示为"孤岛"，
而它们其实和 URL 有明确关系——**孤岛列表被污染，真正没碰的资产淹在噪音里**。

**修法**：引入 `parent_id` 建立三层包含关系，`asset_id` 格式保持不变（不破坏已有数据）。

```
host:10.0.0.5          <- 主机（唯一带 host: 前缀的一层）
  └ 10.0.0.5:80        <- 端口（parent_id = host:10.0.0.5）
      ├ http://10.0.0.5/             <- URL（parent_id = 10.0.0.5:80）
      ├ http://10.0.0.5/admin
      └ http://10.0.0.5/.git/config
```

关键点：

- **父指针自动推导**。`Asset.for_url()` 从 URL 拆 scheme/host/port，端口缺省按 scheme 推
  （http→80、https→443），推出 parent 是 `host:port`；推不出就挂到 host。
- **解析器自动补父节点**。只发现 URL 而没扫端口是常态，所以 `parse_httpx_jsonl` /
  `parse_ffuf_json` 在为 URL 建节点时，顺带补建 host 与 port 节点——否则那条 URL
  在图里就是孤岛。
- **`contains` 边与 `pivots` 边语义严格分开**。`contains` 是部署关系（谁跑在谁上面），
  `pivots` 是攻击跳转（从 A 能到 B）。混在一起会让攻击链里混进一堆部署关系，
  路径就不再是攻击路径。
- **孤岛判定只用 `pivots` 和 `findings`**。一个端口挂在主机下不代表它被探查过。
  但主机节点会因为"有子节点"而不算孤岛，这是对的——有子节点的主机显然被关注过。

**效果**：同一份测试数据，孤岛从 4 个降到 1 个，剩下的是 `10.0.0.5:22`——真正没碰的那个。

**兼容性**：旧数据没有 `parent_id`，建图时 `contains=0`，孤岛判定退回按 `pivots` 算，
不会报错也不会误判。已验证。

### CLI

```bash
python3 graph.py --root findings --build          # 从 JSONL 建图
python3 graph.py --root findings --summary
python3 graph.py --root findings --from http://10.0.0.5/
python3 graph.py --root findings --path A B       # 最短路径
python3 graph.py --root findings --chokepoints    # 必经节点
python3 graph.py --root findings --isolated       # 完全没碰的
python3 graph.py --root findings --critical-paths
```

### 与编排器的连接

`--store-root` 配置后，prompt 注入：

```markdown
## 攻击链概况（资产之间的关系图）
- 已知跳转边 3 条 · 孤立资产 3 个
- **必经节点**（被最多路径穿过，打穿它们收益最高）：
  - http://10.0.0.5/db（3 条路径）
  - http://10.0.0.5/admin（2 条路径）
```

"必经节点"这个说法是刻意的——它比"hub"更能推动行动：如果 `/db` 是三条路径的交汇，它要么是最该打穿的，要么是客户最该保护回来的。

---

## 十、执行层（Rust）

### 三个必须由内核解决的问题

Python 侧原来是 `subprocess.Popen` + `os.killpg`，实测出了三类问题：

**`pkill -f` 自匹配**，六次把自己的 shell 杀掉。用字符串匹配找进程，根本不具备识别力。

**孤儿进程占着内存不放**。浏览器主进程死了，7 个 contentproc 还在，合计 1.3GB。`killpg` 杀的是进程组，而 `setsid` 出来的孙进程早不在原组里。

**OOM 无法归因**。两路 QEMU 各吃 2G 把机器压死，事后说不清是谁吃的。

三者的共同解法是**让内核记账，而不是靠字符串猜**。

### nai-run 做了什么

一个只有 `libc` 依赖的二进制（编译 10s，二进制小）：

```
nai-run --mem 1G --cpu 2 --pids 256 --timeout 900 --idle-timeout 420 --log out.log -- CMD...
→ {"exit":0,"signal":0,"elapsed_ms":16,"peak_mem_kb":256,"timed_out":false,
   "kill_reason":"","killed":0,"oom_kill":0,"limited":true}
```

- **cgroup v2 硬限额**：`memory.max` / `cpu.max` / `pids.max`，超了就是 OOM，不是"尽量"
- **两个超时判据**：`total_wall`（跑太久）与 `idle`（无输出判卡死）。分开是因为两者处理方式不同——一轮扎实的逆向可能 15 分钟都在跑，而卡住的连接 15 分钟一个字都不吐
- **进程树清理**：遍历 `cgroup.procs` 逐个 SIGKILL。**这是 `killpg` 做不到的**
- **OOM 归因**：读 `memory.peak` 和 `memory.events` 里的 `oom_kill` 计数

### 实测证据

```
=== setsid 逃逸测试 ===
子进程用 setsid 自建会话逃出进程组，killpg 杀不到
{"timed_out":true,"kill_reason":"total_wall","killed":1,...}
残留 sleep: 0
```

`killed: 1` 就是那个"killpg 够不到的逃逸者"——cgroup 枚举把它揪出来杀了。

```
=== OOM 归因 ===
{"signal":9,"peak_mem_kb":49152,"oom_kill":1,...}
```

峰值 49152 KB 正好等于 48M 限额，`oom_kill: 1` 是内核记账的触发次数。

```
=== 两个判据区分 ===
卡住场景: kill_reason="idle"        2510ms
跑太久:   kill_reason="total_wall"  2131ms
正常退出: kill_reason=""  不误杀
```

### 关键取舍

**不用 `PR_SET_PDEATHSIG`**：它在 exec 之后被清空，对长命令无效。真正可靠的是 cgroup——子进程即使 exec 过、setsid 过，只要还在 cgroup 里就一定能被枚举出来。

**不用 `cgroup.kill`**：本机内核（6.19.14）没编这个文件。退化为遍历 `cgroup.procs`，效果等价，代价是多几次系统调用。

**降级而非失败**：二进制不存在时退回 `subprocess`，并在结果里标 `supervised=False`。不理想（又回到孤儿问题），但比"执行层没编译好就跑不了任务"要好——**并且调用方能知道自己失去了哪些保障**。

### 顺带修掉的一个真 bug

排查执行层时发现 `run_round` 里这行：

```python
f"…$(cat '{prompt_path}')…"     # ← 中文引号
```

用的是**中文引号**。bash 不认，命令替换结果被按空白拆成几十个参数，`run.sh` 收到的 prompt 是碎的。表现就是**轮次日志 0 字节、DSH 根本没起来，而且全程不报错**——之前几次"启动失败"很可能就是它。

改成环境变量传值：

```python
env["NC_PROMPT_FILE"] = prompt_path
f'"$(cat "$NC_PROMPT_FILE")"'
```

验证：含中文引号、单引号、`$VAR`、反引号的 prompt 被完整传递（50 字符 / 2 行，一个都没碎）。

### 与编排器的连接

```bash
python3 orchestrator.py --challenge example.com --supervised --round-mem 3G ...
```

`--supervised` 默认关闭：裸 subprocess 那条已经跑通过，新路径要显式开启。开启后每轮报告 `last_peak_mem_kb` / `last_oom_kill` / `last_cleaned`。

---

## 十一、端到端验证结果（2026-11-20）

### 验证设计

用一段有明显 check-then-act 竞态的 Python 代码做任务，只看**编排链路**是否打通，不看解题难度。单路、`--supervised`、`--round-mem 2G`、5 分钟上限。

### 结果

```
[orch] verify2 阶段=converge 轮次=0 截止=13:03
[orch] r1 完成 phase=converge 假设=2
[orch] verify2 已产出答案（.../FINDING.md），第 1 轮提前收束，不再开新轮
```

```
round              = 1
supervised         = True
last_peak_mem_kb   = 1340          <- cgroup 记账生效
last_oom_kill      = 0
last_cleaned       = 0
verdicts_total     = 2             <- 裁决闭环打通
salvaged_rounds    = 0             <- agent 自己写了 ROUND.md，没走回捞
hypotheses         = 2
excluded           = 3
假设状态: [('H1','confirmed'), ('H2','confirmed')]
```

产出：`FINDING.md`(1876B) + `ROUND.md`(3479B) + `MEMORY.md`(1809B) + `race_repro.py`(2335B)。
那份复现脚本是真的跑通了，输出 `{'src': -100, 'dst': 200, 'total': 100}`，两次转账都通过了 100 的余额检查。

### 验证过程中挖出并修掉的三个 bug

**1. 中文引号导致 prompt 传参碎裂**（最严重）

```python
f"…$(cat '{prompt_path}')…"     # ← 中文引号
```

bash 不认，命令替换结果被按空白拆成几十个参数。表现是**轮次日志 0 字节、DSH 根本没起来、全程不报错**。之前几次"启动失败"很可能就是它。改用环境变量 `NC_PROMPT_FILE` 传值。

**2. 裁决回填在假设入库之前**（Reflexion 闭环从未工作）

```
850行: judged = 0; for v in verdicts: for h in st["hypotheses"]...
891行: for h in new_hyps: st["hypotheses"].append(...)
```

裁决遍历假设库时本轮新提的假设还没进去，永远匹配不上，`verdicts_total` 一直是 0。修复后从 0 变成 2。**这意味着在此之前，"提出假设→验证→回填裁决"这条闭环根本没跑起来过**，`last_progress_round` 的判据也因此一直失效。

**3. `NC_PROMPT_FILE` 写在 else 分支里**

supervised 路径下拿不到 prompt 文件路径。提到分支外。

### 顺带修掉的环境问题

- `overlay.yml` 被归档后未重建 → DSH 启动报 `failed to read overlay`。现在改成**可选**：文件不在就不传 `--patch`，而不是让启动失败。重建的版本只放开工具与网络，**范围控制交给 Rego**，不再清空白名单。
- `/root/proj/home/sessions/` 里有 root 拥有的目录（早先用 root 手动跑过 DSH），而 DSH 以 zsh 运行 → `EACCES`。`fix-perms.sh` 修好。

### 结论

- 编排链路：**通**
- 执行层 cgroup 限额与记账：**通**
- 跨轮记忆与排除累积：**通**
- 裁决闭环：**通**（修复后）
- 单轮 46~70 秒完成，无资源残留

**未验证**：多轮迭代（本轮第 1 轮就完成收束，没跑到第 2 轮）；真实赛题难度下的表现；`--supervised` 在高负载多路并发下的行为。

---

## 十二、作业形态：黑盒与白盒

### 为什么是两套方法论，不是一个参数

黑盒与白盒的差别不在"有没有源码"，而在**凭什么下结论**：

| | 黑盒 | 白盒 |
|---|---|---|
| 输入 | 域名 / IP 段 / URL | 源码 / 配置 / IaC / 架构 |
| 第一动作 | 资产发现 → 指纹 → 攻击面枚举 | 入口点清单 → 信任边界 → 数据流追踪 |
| 核心方法 | 从响应差异反推内部结构 | 从代码路径推导可达性 |
| 判定依据 | 对照实验（Body-Diff / 唯一性 / 可重放） | **代码位置 + 实际请求**双证据 |
| 主要误报源 | 版本号当结论、单次差异当漏洞 | "看起来危险"当"实际可利用" |
| 典型高估 | 影响范围 | 可达性 |

所以是两份独立规格 `agents/blackbox.md` 与 `agents/whitebox.md`，
不是 `--domain web` 换个取值。

### 用法

```bash
# 黑盒：外部渗透
python3 orchestrator.py --target example.com --mode blackbox --domain web \
  --scope-file scope/example.json --store-root findings --supervised --round-mem 3G

# 白盒：代码审计（把源码放进 attachments/<target>/）
python3 orchestrator.py --target acme-portal --mode whitebox --domain web \
  --store-root findings --supervised --round-mem 3G
```

`--mode` 与 `--domain` 是两个正交维度：
**mode 决定凭什么下结论，domain 决定往哪儿看。**

### prompt 里的顺序

方法论规格排在领域规格**之前**。理由：判定纪律如果被领域细节盖过，
agent 会变成"知道很多攻击手法但下不了结论"——这正是黑盒阶段最典型的失败形态。

### 参数泛化

- `--target` 与 `--challenge` 等价，两者至少给一个。前者是真实作业的语汇。
- `--challenge` 保留是因为既有状态目录按它命名，改名会打断历史。

### 已移除的 CTF 专属能力

| 移除项 | 原因 |
|---|---|
| flag 提交 / 平台判定 | 真实渗透没有"平台判你答案对错" |
| 容器生命周期管理 | 真实目标不会 30 分钟后自动销毁 |
| 分值跟踪 / 出题队伍数 | 无对应概念 |
| 绕过提交门禁检测 | 它保护的是比赛平台的幂等台账 |
| `ANSWER_FILES`（FLAG.txt 语义） | 改为 `DELIVERABLE_FILES`（FINDING / REPORT / EVIDENCE） |

`_ctf-archive/` 保留比赛期间的工具与数据，仅作历史参考，主流程不再引用。
