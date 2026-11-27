# 这套系统的三份说明

一个跑真实渗透任务的多 agent 系统。三篇文章各写一个方向，不重复。

代码：`dsh-secops/`（微层，TypeScript 插件）+ `engine/`（宏层，Python / Rust / Rego）。

---

## 一、设计哲学 —— 《渗透测试 Agent 系统的设计哲学》

📄 [design-philosophy.md](design-philosophy.md) · 460 行

**方向：组织形态。**

三公分权（丞相盘库存、太尉拆解派单、御史管授权限额超时）、副 Agent 热插拔的前提、为什么需要一个主控而不是让 Agent 之间对话、时间驱动和 goal 驱动差在哪、记忆为什么必须是结构而不是上下文。

一句话：**把任务当契约派出去，只回一份报告，别让 agent 之间互相聊。**

代码：`src/council/`（chancellor / marshal / censor / roster / contract）

---

## 二、执行层 —— 《Linux 进程树为什么杀不干净》

📄 [process-tree-cleanup.md](process-tree-cleanup.md) · 372 行

**方向：进程与资源。**

`killpg` 为什么杀不干净（`setsid` 逃逸），`PR_SET_PDEATHSIG` 为什么不够（不管孙进程），最后为什么只能靠 cgroup 记账。附带内存归因：`peak_mem_kb`、`oom_kill` 计数怎么变成可靠证据。

一句话：**不要用信号去杀一棵树，因为"树"这个关系在内核里不存在。**

代码：`engine/runner/src/main.rs`（333 行）、`engine/runner.py`

---

## 三、证据层 —— 《Agent 的自述为什么不能作为证据》

📄 [agent-self-report-is-not-evidence.md](agent-self-report-is-not-evidence.md) · 293 行

**方向：可信度。**

独立路径数为什么不等于证据。模型自述的 `executed` 字符串和系统记录的 argv 文本完全一样，凭什么一个算 weak 一个算 strong。锚点怎么从断言里确定性提取。四组对照实验：同样两条路径、三种命运。

一句话：**信任来源不能推断，只能置位。**

代码：`src/relevance.ts`、`src/provenance.ts`、`src/provenance-tools.ts`

---

## 阅读次序

想理解**为什么这么设计**：从第一篇开始。

想确认**这些东西真的能跑**：第二、三篇都是可复现实验，配了真实运行输出。

三篇共同的立场：**能算准的事交给代码，别交给模型的自述。** 第一篇说 agent 之间不该靠对话协调，第二篇说进程树不该靠信号杀，第三篇说证据不该由模型担保——同一条线切三次。

---

## 实验与复现

`docs/exp/` 下是第二、三篇用到的复现脚本，都能独立跑：

- `orphan.c` — 复现 7 个占内存的孤儿进程
- `pdeath.c` / `pdeath2.c` — 验证 `PDEATHSIG` 在 exec 后有效、但不被孙进程继承
- `hog.py` — 逐渐吃内存，用来对照内存限额
- `render.py` — 把终端输出渲染成文章里的图（等宽 + 中文）

每篇末尾都有"怎么自己验一遍"。

---

## 还没解决的

写在每篇的"代价"一节里，这里列最要紧的三条：

`pathKey` 的独立性仍然是模型声明的，不是系统核实的；覆盖率账本在 cgroup 层面的横向扩展没测过；这套东西还没有在真实客户项目上完整跑过一轮。
