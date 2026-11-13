# dsh-secops

安全测试编排的领域层插件，挂在 DSH 原生接缝上。

不是 agent，不是 harness，是一层**策略与决策**：范围闸、预算闸、停止条件。

## 为什么是插件

DSH 的架构文档写明「**不存在需要打补丁的特权内核**：扩展 dsh 的方式是把插件挂载到其他插件旁边」。所以本包不修改任何 `@deepseek-ai/*` 源码，只注册到既有接缝：

| 职责 | 接缝 | 语义来源 |
|---|---|---|
| 范围闸 | `ctx.tools.guard()` | 单调拒绝，任何 guard 不能 force-allow 另一个 guard 的拒绝 |
| 预算闸 | `ctx.tools.guard()` | 同上，计数与墙钟 |
| 停止条件 | `agent/pre-step` waterfall | 返回 `{ kind: 'reject' }` → turn 以 `blocked` 结束 |

`inject = ['tools']`：没有 tools 服务时插件保持 PENDING，不会带半套策略跑起来。

## 配置

```yaml
- name: 'dsh-secops'
  config:
    allowedHosts:
      - authorized.example
      - 10.0.0.15
    maxToolCalls: 300
    maxWallClockMs: 600000
    maxSteps: 40
    logDecisions: true
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `allowedHosts` | `string[]` | 授权目标主机，精确匹配（大小写不敏感）。空数组 → 范围闸不生效 |
| `maxToolCalls` | `number` | 工具调用总次数上限，从插件加载计入 |
| `maxWallClockMs` | `number` | 墙钟预算（毫秒），从插件加载起算 |
| `maxSteps` | `number` | 单 turn 步数上限，超过则 pre-step 返回 reject |
| `logDecisions` | `boolean` | 是否把决策写入日志，默认 `true` |

全部配置在加载期校验；非法值直接抛错，不留到运行期。

## 已知限制（重要）

**范围闸是静态文本提取，不是网络强制。**

`ctx.tools.guard()` 的签名是同步的 `(exec) => string | undefined`：不能做 DNS 解析、不能跟随重定向、看不到实际连接地址。当前实现只从工具参数里提取 `http(s)://host` 形态的目标，裸域名和 IP 不提取（误判率太高，宁可放行并计数）。

因此：

- 它能拦住「明显越界」的调用
- 它拦不住 `bash -c 'curl --resolve ...'`、动态拼接的命令、以及任何解析不出来的形态
- **真正的强制必须在网络层**：`ctx.sandbox` 是可替换 seam，`SandboxProvider.confine()` 返回的 bwrap argv 里加 `--unshare-net`，再配 netns + egress proxy。DSH 自带的 bwrap profile 没有 `--unshare-net`

把这条限制写在前面，是因为把 guard 当成网络隔离会让整个证据链失真。

**决策阶段只做 reject，不注入方向。**

构造合法的 `UserMessage` 需要正确的 `source`/`form`，容易出错。注入方向有更干净的落点：`ctx.systemPrompt` 贡献段 + `planMode` 的 deployment-owned guidance 配置。

**安全闸不能放 pre-step。**

cordis 的 `prepend` 是 `unshift`，后注册者更靠前——`agent/pre-step` 的顺序不保证。所以拦截一律走 `guard`，它按语义单调，与顺序无关。

## 验证状态

| 项 | 结果 |
|---|---|
| `tsc -p tsconfig.json` 对 **0.2.2-rc.1** 类型，strict + NodeNext + `skipLibCheck: false` | **通过**，exit 0 |
| `tsc -p tsconfig.json` 对 **0.1.5-rc.1** 类型 | **通过**，exit 0 |
| `tsc -p tsconfig.build.json` 产出 `dist/` | **通过**，4 个 .js 文件 |
| 产物加载（`import('./dist/index.js')`） | **通过**，导出 `apply` / `inject` / `name` |
| 行为冒烟 `test/smoke.mjs` | **15/15 passed** |
| 决策记录持久化 `test/decision.mjs`（写入 → projection → 读回） | **10/10 passed**（0.2.2） |
| 跨进程队列 `test/queue.mjs`（执行/幂等/超时/恢复/并发） | **13/13 passed** |
| 队列工具 `test/queue-tools.mjs`（worker_submit / worker_status） | **8/8 passed** |
| Provenance 判据 `test/provenance.mjs`（独立复现 / 证伪单向） | **22/22 passed** |
| Provenance 集成 `test/provenance-session.mjs`（claim → projection） | **6/6 passed** |
| 网络出口 `test/egress.mjs`（netns 断连 / 代理 allow-deny / fail closed / 宿主不受影响） | **9/9 passed** |
| 队列 + netns `test/netns-queue.mjs` | **3/3 passed** |
| 证据自动归档 `test/evidence-archive.mjs`（产物 → claim 证据） | **21/21 passed** |
| 证据相关性 `test/relevance.mjs`（锚点匹配 / 自述不可绕过） | **25/25 passed** |
| 跨会话持久化 `test/persistence.mjs`（重启后 claim/证据/证伪状态保持） | **14/14 passed** |
| 证据可重放 `test/replay.mjs`（骨架归一化 / 重放校验 / 篡改检测） | **23/23 passed** |
| 决策纪律 `test/decision-policy.mjs`（空理由 / 重复拒绝 / 空转） | **19/19 passed** |
| 失败注入 `test/failure-injection.mjs`（磁盘失败 / 损坏文件 / 超时孤儿 / 代理未启动） | **16/16 passed** |
| Model Fallback `test/model-fallback.mjs`（该切/不该切 / 顺序 / 额度 / 多 agent） | **32/32 passed** |
| 端到端运行（真实会话中触发 guard 拒绝 / pre-step reject） | **0.1.5 已验证**，见下 |
| 0.2.2 运行时 `ctx.tools.checkGuards()` | **通过**：授权 ALLOW / 越界 DENY |
| **0.1.5 整体** | **不兼容**：`appendPluginRecord` 不存在，决策记录需 0.2.2 |

行为冒烟覆盖：配置归一化、目标提取（URL / bash 命令 / 非 URL 参数 / null）、范围内放行、范围外拒绝、IP 白名单、预算计数到点拒绝、pre-step 注册、步数超限 reject、上游 reject 不被覆盖。

命令：

```sh
npm run check   # 类型检查
npm run build   # 构建 dist/
node test/smoke.mjs
```

未做端到端的原因：需要干净安装的 DSH profile，而当前环境的实例被 `dsh-purge` 打过 36 处 patch（审批自动批准、沙箱升级永不被拒、文件围栏关闭），任何权限类验证在那里都是假阴性。

## 目录

```
src/
  index.ts      插件入口，组合三个模块
  config.ts     配置类型 + 加载期校验
  guards.ts     范围闸与预算闸
  decision.ts   决策阶段（pre-step）
```
