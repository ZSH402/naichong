# 奶虫（nai-chong）

**把「每个结论都要有可复核的证据」做成代码约束，而不是提示词。**

跑在 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 之上，服务于真实渗透作业的黑盒与白盒两种形态。

```
dsh-secops（TypeScript）  微观：这条结论可不可信
engine/（Python/Rust/Rego）宏观：这段作业在收敛还是在原地打转
```

---

## 它解决什么问题

LLM agent 做安全测试，最常见的失败不是「找不到漏洞」，而是两类结构性问题：

**第一类：找不到却说找到了。** 报一个越权，实际接口本来就那么返回；报一个缺加固，实际是检测器自己坏了。这类问题的根子在于**单条结论缺少可复核性**——模型的自述被当成了证据。

**第二类：一直在跑，但没在前进。** 收集了一堆子域、端口、指纹，没有一个验证过的洞；或者在同一个思路上反复微调，每轮都以为「快要有结论了」。这类问题的根子在于**多轮作业缺少收敛机制**——没人看趋势，没人记住已经排除了什么。

这两类问题分属两个尺度，所以这个项目有两层。它们不是同一个东西的两个版本，解决的是不同层面的失效。

## 两层分别管什么

| | dsh-secops（微观） | engine（宏观） |
|---|---|---|
| 作用点 | 每次工具调用返回之后 | 每一轮作业结束后 |
| 回答的问题 | 这条证据够不够格支撑这个断言 | 这几轮是在收敛还是在打转 |
| 失效形态 | 误报、把默认值当漏洞 | 无限探索、重复劳动、预算烧光 |
| 强制手段 | 在 `tools/pre-execute` 返回 `deny` | 时钟注入 / 记忆文档 / 停滞检测 |
| 判定粒度 | `none` / `reproducible` / `calibrated` / `cross-checked` | 连续无进展 / 高回捞率 / 零裁决 / 假设堆积 |

两者可以独立使用。只用 dsh-secops 时你得到的是「结论不会太假」；只用 engine 时你得到的是「作业不会跑飞」。一起用时，engine 每轮的产出仍要过 dsh-secops 的闸。

## 核心机制

### 微观层（dsh-secops）

| 机制 | 拦的是什么 |
|---|---|
| 相关性闸 | 命令或请求的产出必须触及断言锚点，自述不算证据 |
| 重放闸 | 支持重放的证据会再跑一次，严格摘要不一致就降级 |
| baseline / control | 只有 proof 没有对照的结论标为弱；二进制加固这类没有「正常态」可比的，用已知样本校准检测器 |
| 验证档位 | 四档不压成一个布尔 |
| 误报账本 | 按工具统计「报了多少、被推翻多少」，只算明确归因的推翻 |
| 奖惩信誉 | 判断准不准进入调度排序；旧战绩按半衰期衰减，失误有地板不会一票否决 |
| 捷径拦截 | 直接读 flag、跑靶机 setuid helper、用容器命令绕过边界——第一次就拒 |

### 宏观层（engine）

| 机制 | 解决的是什么 |
|---|---|
| 时钟注入 | 每轮把「现在几点、还剩多久」写进上下文。模型没有时间感，实测它开赛五分钟还以为没开赛 |
| 跨轮记忆 | `MEMORY.md` 只放三类：已确认 / 已排除 / 悬而未决。**不放原始日志**——那是污染源 |
| 已排除累积 | 单轮 `ROUND.md` 里的「此路不通」按路径去重进 state，下一轮单列一节 |
| 停滞检测 | 四条判据，命中 ≥2 条判定停滞，自动切探索档并把理由注入下一轮 |
| 假设闭环 | 提出 → 验证 → 裁决回填，判死的进 `refuted` 不许再碰，判活的进 `confirmed` 不许重复验 |
| 产出即收束 | 写完交付物就停，不要为「更保险」再跑一轮 |
| 授权范围闸 | 范围从 Python 的 `if` 挪到 Rego：默认拒绝、可单测、可审计 |
| 数据查询 | DuckDB 直读扫描产物 JSONL，回答「还有哪些资产完全没碰」 |
| 攻击路径 | Kùzu 图做可达性、最短路径、枢纽分析 |
| 受监管执行 | Rust + cgroup v2：硬限额、双超时判据、遍历 `cgroup.procs` 清理逃逸进程 |

## 目录

```
dsh-secops/            微观层（TypeScript）：断言与证据、方向调度、三公分工、奖惩信誉
engine/                宏观层（Python）：多轮编排、数据契约、策略、查询、图、执行
  orchestrator.py        编排主循环：时钟 / 收敛 / 假设 / 记忆 / 停滞
  models.py              Pydantic 数据契约（跨层边界不用裸 dict）
  policy/scope.rego      授权范围策略（默认拒绝，15 条 Rego 单测）
  scopegate.py           策略的 Python 侧（fail-closed）
  store.py               DuckDB：Asset / Finding / Evidence / Edge
  graph.py               Kùzu 图：攻击路径推理
  runner.py + runner/    Rust 执行层（cgroup 限额 + 进程树清理）
  agents/                方法论与领域规格
    blackbox.md            黑盒方法论
    whitebox.md            白盒方法论
    web.md / pwn.md / crypto.md / misc.md / reverse.md / ai-security.md
dsh-client-ui-secops/  浏览器面板（claim 账本、按工具战绩、时间信用、凭据状态）
desktop/               Electron 桌面壳（宿主由 shell 起，Electron 只当窗口）
config/                cordis 配置模板（已脱敏）
docs/                  设计文档与实战暴露的问题
scripts/               repair.sh（依赖树修复）、fix-perms.sh（属主修复）
```

## 装

### 微观层

前提：Node ≥ 22、一个可用的 DSH 版本、kali 类发行版（工具链按需）。

```bash
cd dsh-secops && npm install && npm run build

# 挂进 DSH：把 config/cordis.patch.yml.example 复制成
# $DSH_HOME/profiles/<profile>/cordis.patch.yml，按注释填路径与凭据
./sync-to-runtime.sh

# 验证
cd dsh-secops && for t in smoke provenance agent-dispatch council credit control wiring; do
  node test/$t.mjs | tail -1
done
```

### 宏观层

前提：Python ≥ 3.11、`opa`、`cargo`（执行层需要）。

```bash
cd engine
pip install pydantic duckdb kuzu

# 编译执行层（可选，但强烈建议：没有它就没有进程树清理和内存限额）
cd runner && cargo build --release && cd ..

# 授权范围（必填）
cp scope/example.json scope/mine.json   # 填 cidrs / hosts / tools

# 验证
pa test policy/                         # 15 条策略单测
python3 store.py --root /tmp/t --help   # 数据层
python3 orchestrator.py --help
```

### 跑一次

```bash
# 黑盒：只有域名 / IP 段
python3 orchestrator.py \
  --target example.com --mode blackbox --domain web \
  --scope-file scope/mine.json --store-root findings \
  --supervised --round-mem 3G --deadline-min 60

# 白盒：源码放进 attachments/<target>/
python3 orchestrator.py \
  --target acme-portal --mode whitebox --domain web \
  --store-root findings --supervised --round-mem 3G --deadline-min 60
```

`--mode` 决定**凭什么下结论**，`--domain` 决定**往哪儿看**。两个维度正交。

## 黑盒与白盒

不是同一个 prompt 换个参数，是两套方法论（`engine/agents/blackbox.md` 与 `whitebox.md`）。

| | 黑盒 | 白盒 |
|---|---|---|
| 输入 | 域名 / IP 段 / URL | 源码 / 配置 / IaC / 架构 |
| 第一动作 | 资产发现 → 指纹 → 攻击面枚举 | 入口点清单 → 信任边界 → 数据流追踪 |
| 核心方法 | 从响应差异反推内部结构 | 从代码路径推导可达性 |
| 判定依据 | 对照实验（Body-Diff / 唯一性 / 可重放） | **代码位置 + 实际请求**双证据 |
| 主要误报源 | 版本号当结论、单次差异当漏洞 | 「看起来危险」当「实际可利用」 |
| 典型高估 | 影响范围 | 可达性 |

两份规格都写了「何时该转另一种」。白盒容易高估影响，黑盒容易低估，同一份报告里两种视角都该有。

方法论规格在 prompt 里排在领域规格**之前**。理由：判定纪律如果被领域细节盖过，agent 会变成「知道很多攻击手法但下不了结论」——这正是黑盒阶段最典型的失败形态。

## 设计上的几个取舍

**证据不是日志。** 一条证据必须能被第三方重跑复现；重跑得到不同结果，它的档位就降下来。

**`cross-checked` 和 `calibrated` 互不替代。** 前者是「目标行为已对照」，后者是「检测方法已校准」。二进制加固、TLS 配置没有「目标正常态」可比，能证明的只有后者。把两者混成一档，等于用「工具可信」冒充「目标已对照」。

**信誉用 Beta 后验而不是朴素比率。** 1 次成功不该显示成 100%。先验 `Beta(1,1)` 同时是惩罚的地板：一次失误把分数从 0.5 压到 0.33，成功一次就回到 0.5。

**没跑过的牌按中性算，不给零分。** 评分函数如果对零样本返回 0，新工具永远排最后、永远拿不到样本。

**约束落成代码，不靠提示。** 捷径拦截是在 `tools/pre-execute` 返回 `deny`，不是往上下文里塞一句「请不要」。提示会被绕过，拒绝不会。

**跨轮记忆里不放原始日志。** 记忆文档只放三类结论。原始日志里全是失败尝试和挫败感，喂回去只会让下一轮更没方向。这是从 Archon（北大的 Lean 形式化 agent）学到的：它明确把「agent 自己的失败尝试会侵蚀其坚持意愿」列为规模化后的首要问题。

**已排除路径必须跨轮累积。** 它比「上一轮我干了什么」更能防止原地打转。之前它只活在单轮产物里，解析完就丢，等于每轮从零开始排除。

**停滞检测用规则而不是再叫一次模型。** 四条判据全是跨轮累积量，零成本。为「我们是不是卡住了」单独付一次模型调用不划算——除非预算宽裕到不在乎。

**数据契约用 Pydantic 而不是裸 dict。** 教训具体：曾有一条裁决因为写成 `refuted（…）`（中文括号）而被整串比对漏掉，且不报错，闭环静默停摆好几轮。校验必须发生在**写入时刻**，而不是消费时刻。

**执行层的进程清理靠 cgroup 而不是字符串匹配。** 用 `pkill -f` 找进程，实测六次把自己的 shell 杀掉；`killpg` 够不到 setsid 出来的孙进程，实测留下 7 个孤儿占 1.3GB。可靠的做法只有让内核记账：cgroup 圈住整棵树，遍历 `cgroup.procs` 枚举真正的成员。

**不建表导入，用 VIEW 直接映射文件。** 扫描产物持续产生，每次导入一遍（ETL）本身就是负担。DuckDB 能直接读 JSONL，数据落盘即可查。

## 实测数据

比赛期间（2026-11，已停止用于 CTF）跑过的基线，仅作性能参考：

- 编排链路端到端：单轮 46~70 秒完成，产出 `FINDING.md` + `ROUND.md` + `MEMORY.md`
- 执行层 cgroup 记账：峰值内存 1340 KB（2G 限额下未触发 OOM）
- 进程树清理：`setsid` 逃逸的孙进程能被 `killed` 计数捕获，残留 0
- 策略层：15 条 Rego 单测全过，含「子域不等同父域授权」「空范围必须拒绝」等边界

一个反例值得记：跨轮记忆断裂时，5 路并行各跑 1003 秒，`ROUND.md` 一个都没写出，假设库全是 0——每轮都在侦察半途被砍，下一轮从零重来。修复跨轮回捞后，同样的任务一轮 46 秒就收敛了。

## 已知边界

- 缺陷分类与规则主要面向 Web / 二进制 / TLS / 内网侦察；`post-exploit` 方向目前没有可用候选
- 奖惩信誉吃的是「已定论」的 claim，一次短任务可能攒不出样本，冷启动期主要靠探索项
- claim 记录依赖 `exec.agent.session`，在某些组合下 session log 里拿不到（宿主侧的模块实例问题），面板因此改读 `claims.jsonl`
- MCP 类工具的判据按各工具自己的输出格式写，换版本可能需要跟着改
- 资产三层标识（host → port → url）依赖写入时统一口径；旧数据没有 `parent_id` 时图里不出包含边，孤岛判定会退回按攻击跳转算
- 执行层需要 cgroup v2 可写。容器内通常不可用，此时会降级为裸 subprocess 并在结果里标 `supervised=False`——调用方能知道自己失去了哪些保障

## 许可

私有项目，未授权分发。
