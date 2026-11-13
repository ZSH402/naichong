# dsh-secops

异构安全测试编排层。把「每个结论都要有可复核的证据」这条要求，做成代码约束，而不是提示词。

跑在 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 上，作为 cordis 插件树的一部分。

---

## 它解决什么问题

LLM agent 做安全测试时最常见的失败不是「找不到漏洞」，而是**找不到却说找到了**——报一个越权，实际接口本来就那么返回；报一个缺加固，实际是检测器自己坏了。

这个项目不试图让模型更聪明，它做的是让**不可靠的结论出不来**：

| 机制 | 拦的是什么 |
|---|---|
| 相关性闸 | 命令或请求的产出必须触及断言锚点，自述不算证据 |
| 重放闸 | 支持重放的证据会再跑一次，严格摘要不一致就降级 |
| baseline / control | 只有 proof 没有对照的结论标为弱；二进制加固这类没有「正常态」可比的，用已知样本校准检测器 |
| 验证档位 | `none` / `reproducible` / `calibrated` / `cross-checked`，四档不压成一个布尔 |
| 误报账本 | 按工具统计「报了多少、被推翻多少」，只算明确归因的推翻 |
| 奖惩信誉 | 判断准不准进入调度排序；旧战绩按半衰期衰减，失误有地板不会一票否决 |
| 捷径拦截 | 直接读 flag、跑靶机 setuid helper、用容器命令绕过边界——第一次就拒 |

## 目录

```
dsh-secops/            核心插件：断言与证据、方向调度、三公分工、奖惩信誉
dsh-client-ui-secops/  浏览器面板（claim 账本、按工具战绩、时间信用、凭据状态）
desktop/               Electron 桌面壳（宿主由 shell 起，Electron 只当窗口）
scripts/               repair.sh（依赖树修复）、fix-perms.sh（属主修复）
config/                cordis 配置模板（已脱敏，用前填自己的值）
docs/                  PLAN.md（设计文档）、实战暴露的问题、决策层设计
```

## 装

前提：Node ≥ 22、一个可用的 DSH 版本、kali 类发行版（工具链按需）。

```bash
# 1. 构建核心插件
cd dsh-secops && npm install && npm run build

# 2. 挂进 DSH：把 config/cordis.patch.yml.example 复制成
#    $DSH_HOME/profiles/<profile>/cordis.patch.yml，按里面的注释填路径与凭据
#    然后同步编译产物到 runtime 的 node_modules/dsh-secops
./sync-to-runtime.sh

# 3. 验证
cd dsh-secops && for t in smoke provenance agent-dispatch council credit control wiring; do
  node test/$t.mjs | tail -1
done
```

桌面版：

```bash
cd desktop && npm install        # 需要 electron
./launch.sh                      # 双击 dsh-secops.desktop 也是它
```

`launch.sh` 用 shell 起宿主（`dsh web`），Electron 只负责显示。这条分工是刻意的——让 Electron 去 spawn 宿主时，宿主会继承 GUI 进程的环境，实测同一个命令在 shell 里能起、从 Electron 里 spawn 就报插件激活失败，而且详细诊断不进 Electron 的 stdout。

## 设计上的几个取舍

**证据不是日志。** 一条证据必须能被第三方重跑复现；重跑得到不同结果，它的档位就降下来。

**`cross-checked` 和 `calibrated` 互不替代。** 前者是「目标行为已对照」（知道正常情况返回什么），后者是「检测方法已校准」（知道这个工具在已知样本上是对的）。二进制加固、TLS 配置没有「目标正常态」可比，能证明的只有后者。把两者混成一档，等于用「工具可信」冒充「目标已对照」。

**信誉用 Beta 后验而不是朴素比率。** 1 次成功不该显示成 100%。先验 `Beta(1,1)` 同时是惩罚的地板：一次失误只把分数从 0.5 压到 0.33，成功一次就回到 0.5。信誉系统普遍让坏消息更可信，但在这里非对称换来的灵敏度，代价是一次误判毁掉一张好牌。

**没跑过的牌按中性算，不给零分。** 评分函数如果对零样本返回 0，新工具永远排最后、永远拿不到样本。

**约束落成代码，不靠提示。** 捷径拦截是在 `tools/pre-execute` 返回 `deny`，不是往上下文里塞一句「请不要」。提示会被绕过，拒绝不会。

## 已知边界

- 缺陷分类与规则主要面向 Web / 二进制 / TLS / 内网侦察；`post-exploit` 方向目前没有可用候选
- 奖惩信誉吃的是「已定论」的 claim，一次短任务可能攒不出样本，冷启动期主要靠探索项
- claim 记录依赖 `exec.agent.session`，在某些组合下 session log 里拿不到（宿主侧的模块实例问题），面板因此改读 `claims.jsonl`
- MCP 类工具的判据按各工具自己的输出格式写，换版本可能需要跟着改

## 许可

私有项目，未授权分发。
