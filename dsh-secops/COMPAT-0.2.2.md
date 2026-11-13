# dsh-secops 在 0.2.2-rc.1 上的兼容性验证

## 结论

**dsh-secops 源码无需修改即可在 0.2.2 上工作。** 类型检查与运行时 guard 行为均已实测通过。

## 1. API 差异核对（0.1.5 → 0.2.2）

dsh-secops 只用三个 API，逐个核对：

| API | 0.1.5 | 0.2.2 | 变化 |
|---|---|---|---|
| `ToolGuard` 类型 | `(execution) => string \| undefined` | 同 | **无** |
| `ctx.tools.guard(guard)` | `() => void` | 同 | **无** |
| `ToolExecutionInput` 字段 | callId / name / arguments / agent? / signal | 同，**多 `schema?`**（可选） | 向后兼容 |
| `agent/pre-step` payload | agent / messages / turn / step / signal | 同，**多 `modelSelection`**（只读） | 向后兼容 |
| `PreStepDecision` | `reject` \| `enter` | 同 | **无** |

新增的都是可选字段，dsh-secops 不依赖它们，因此无需改动。

## 2. 结构性变化：tools 拆包

0.1.5 的 `dsh-tools/lib/index.js` 是单文件；0.2.2 拆成了：

```
lib/index.js      registry + guard + restrict
lib/pipeline.js   pre / guard / around / post / result 编排
lib/executor.js   可插拔执行器（ToolExecutor 接口）
lib/batch.js      批量调度
lib/contracts.js  类型契约
```

引入了一个新能力：**ToolExecutor 变成可插拔**。`ctx.tools.execute()` 不再直接跑工具体，而是 `this.selectExecutor(input.agent).execute(input)`。

### 关键问题：换 executor 会不会绕过 guard？

不会。实测调用链：

```
pipeline.js:402
  const denialReason = decision.kind === "allow" ? this.tools.checkGuards(exec) : decision.reason;
```

`checkGuards` 在 **core pipeline** 里执行，位置是 pre-execute 策略与审批之后、dispatch 之前。executor 只是下游的执行者，看不到 guard 之前的状态。

**所以 dsh-secops 的拦截点在 0.2.2 上仍然位于唯一必经路径上。**

## 3. 实测

### 类型检查

```
tsc -p tsconfig.json   (strict + NodeNext + skipLibCheck: false)
对 0.2.2-rc.1 的 .d.ts  → exit 0
对 0.1.5-rc.1 的 .d.ts  → exit 0
```

两版同时通过，说明源码落在两版 API 的交集内。

### 运行时 guard

在 0.2.2 的真实 `ctx.tools` 上直接调 `checkGuards()`：

```
授权目标 https://authorized.example/x  => ALLOW
越界目标 https://evil.example/x        => DENY
  理由: [secops/scope] target "evil.example" is outside the authorized scope (allowed: authorized.example)
```

guard 注册、作用域解析、拒绝理由生成三件事在 0.2.2 上全部正常。

## 4. 未验证项

- **完整 `ctx.tools.execute()` 端到端**：0.2.2 要求先提供 `ToolExecutor` 实例，本环境未提供，因此只验证到 `checkGuards` 这一层。由于 guard 在 pipeline 层、executor 在下游，此处的缺口不影响"guard 是否生效"的结论，只影响"工具体是否真的被执行"。
- **真实会话端到端**：需要完整安装 0.2.2（90 个依赖）并配置 profile。npm/pnpm 在本环境多次超时（已排除镜像问题，`registry.npmmirror.com` 已绕开），未完成。
- **pre-step 的 reject 路径**：`PreStepDecision` 形状未变，payload 新增字段可选，预期无影响，但未在 0.2.2 真实会话里触发过。

## 5. 验证环境构造方式

完整安装失败后，采用定向构造：

1. 从 `registry.npmjs.org` 直接拉取 0.2.2-rc.1 的各子包 tarball
2. 解压到 `/root/dsh-new/pkgs/<name>/package`
3. 用符号链接拼出 `@deepseek-ai` 树（`/root/dsh-022-sim`）
4. 第三方依赖从 0.1.5 的 `node_modules` 复用，版本冲突的两个（`schemastery`、`cordis`）单独拉正确版本

踩到的坑记录：

- npm registry 被配置成 `registry.npmmirror.com`，同步慢是安装卡死的首要原因
- TypeScript 默认把 symlink 解析成真实路径，导致依赖查找跑偏，需要 `preserveSymlinks: true`
- Node 的 ESM 解析**不**遵循 `preserveSymlinks`，需要真实路径上也有 `node_modules`
- `dsh-tools` 用的是 `@deepseek-ai/schemastery` 的 `z`，不是 `zod` 的 `z`；版本 3.18.2 → 3.19.0 之间 `Schema` 泛型参数个数变了
