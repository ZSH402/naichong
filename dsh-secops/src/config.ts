/**
 * 配置解析与校验。
 *
 * 不引入 schemastery：这个插件的配置面很小，手写校验能让失败信息直接指向出错字段，
 * 也少一层依赖。所有值都在加载期校验，不留到运行期才发现。
 */

export interface SecopsConfig {
  /** 授权目标主机名，精确匹配（大小写不敏感）。为空则范围闸不生效。 */
  allowedHosts?: string[]
  /** 工具调用总次数上限。达到后 guard 拒绝后续调用。 */
  maxToolCalls?: number
  /** 墙钟预算（毫秒），从插件加载起算。 */
  maxWallClockMs?: number
  /** 单个 turn 的步数上限，超过则 pre-step 返回 reject。 */
  maxSteps?: number
  /** 是否把决策记录写入日志。默认 true。 */
  logDecisions?: boolean
  /**
   * 整类禁用的工具名（精确匹配）。用于「这个 profile 不许有联网搜索能力」这类硬约束。
   * 与 allowedHosts 互补：范围闸管目标，denylist 管能力。
   */
  deniedTools?: string[]
  /**
   * 网络出口强制。启用后队列任务在独立 netns 中运行，
   * 只有代理 socket 是出站通道，代理按 allowedHosts 放行。
   */
  egress?: { enabled?: boolean; socketPath?: string }
  /**
   * 模型 fallback：主 provider 失败时按顺序切到备用路由。
   * routes 为空或只有一条时不生效。
   */
  fallback?: {
    routes?: { provider: string; model: string }[]
    /** 单个 agent 最多切换几次，默认 3。 */
    maxSwitches?: number
  }
  /**
   * HITL：高风险操作的人工/独立审核。默认关闭，显式开启后
   * 写/破坏/C2 类操作会走 ctx.approval；硬底线始终由 guard 拒绝。
   */
  hitl?: {
    enabled?: boolean
    /** 免审批的工具名（仍然要过范围闸与预算闸）。 */
    allowlist?: string[]
    /** 需要审批的风险等级。 */
    requireApproval?: ('read' | 'write' | 'destructive' | 'c2')[]
  }
  /** 断言/证据归属。默认启用。 */
  provenance?: {
    enabled?: boolean
    /**
     * 相关性校验严格模式（默认 true）：断言没有可核对锚点时直接拒绝证据。
     * 关掉会让「存在越权」这类抽象断言也能挂证据，但那就退回只数路径不校验语义。
     */
    strict?: boolean
    /**
     * 跨会话快照文件（JSONL）。配置后 claim 库在进程重启后仍然存在，
     * 同一 engagement 的多轮会话可以共享事实库。不配置则仅存活于当前会话。
     */
    store?: string
  }
  /** 跨进程任务队列。不配置则不启用。 */
  queue?: {
    enabled?: boolean
    /** 队列 JSONL 路径。默认 <cwd>/.dsh-secops/queue.jsonl */
    file?: string
    /** 证据根目录。默认 <cwd>/.dsh-secops/evidence */
    evidenceRoot?: string
    concurrency?: number
    timeoutMs?: number
    /** 启动时把上次遗留的 running 任务自动重投。 */
    requeueInterrupted?: boolean
  }
  /**
   * 方向级 agent 调度。依赖 queue（复用同一执行器与证据目录）。
   * 不配置则按 queue 的启用状态自动启用。
   */
  agentDispatch?: {
    enabled?: boolean
    /** 最多尝试几个 agent，默认 2（一次主力 + 一次兜底）。 */
    maxAttempts?: number
    /** 单次派活的墙钟上限，默认 5 分钟。 */
    overallTimeoutMs?: number
    /** 累计代价权重上限，默认 10（cheap=1 / moderate=3 / expensive=10）。 */
    costBudget?: number
    /** 跑通但没定论时是否自动换下一个，默认 false。 */
    stopOnInconclusive?: boolean
    /** 同一类故障连续几次熔断，默认 2。 */
    faultCircuit?: number
  }
  /**
   * 时间信用：基础额度 + 按认知进展续期。
   *
   * 和「预算」不是一回事：预算管花多少，这里管「值不值得继续给时间」。
   * 进展必须由 ClaimStore 判定（假设带 falsifier、证据过锚点校验、证伪落库），
   * 模型自己说「有线索」不续期。
   */
  timeCredit?: {
    enabled?: boolean
    /** 基础额度，默认 30 分钟。 */
    baseMs?: number
    /** 每次有效进展续期，默认 10 分钟。 */
    grantMs?: number
    /** 总额度上限，默认 2 小时。 */
    maxMs?: number
    /** 两次续期最小间隔，默认 2 分钟。 */
    grantCooldownMs?: number
    /** 剩余低于此值提醒收尾，默认 5 分钟。 */
    warnAtMs?: number
    /** 每次判定为原地打转扣多少时间，默认 5 分钟。 */
    debitMs?: number
    /** 扣减总额上限，默认 15 分钟。设 0 等于关掉惩罚这一半。 */
    maxDebitMs?: number
    /** 两次扣减最小间隔，默认 5 分钟。 */
    debitCooldownMs?: number
  }
  /**
   * MCP server 接入（CyberStrikeAI / rea / hexstrike 这类只以 MCP 形态存在的东西）。
   *
   * 没有这一层时它们只能停在「编译好了但用不上」。
   */
  mcp?: {
    enabled?: boolean
    /** 启动命令，例如 ["/path/to/cyberstrike-mcp", "-config", "/path/to/config.yaml"] */
    command?: string[]
    cwd?: string
    timeoutMs?: number
  }
  /**
   * ARTEX 专项执行者（外部服务）。
   * 只负责「给目标、拿 findings」，编排仍在本地——不让它自己决策。
   */
  artex?: {
    enabled?: boolean
    /** 后端地址，例如 http://127.0.0.1:8787 */
    baseUrl?: string
    /** 登录密码。 */
    password?: string
  }
  /**
   * 三公：丞相（分析）/ 太尉（调度）/ 御史大夫（风控）。
   * 默认跟随 agentDispatch——没有调度就没有可审的对象。
   */
  council?: {
    enabled?: boolean
    rateWindowMs?: number
    rateMaxPerWindow?: number
    /** 同方向连续失败几次开闸。 */
    breakerThreshold?: number
    breakerCooldownMs?: number
    /** 授权目标主机白名单，空数组表示不约束。 */
    allowedHosts?: string[]
    /**
     * 奖惩信誉：把「判断准不准」变成调度排序的输入。
     *
     * 默认开启。关掉之后系统仍然记录确认/推翻，但排序退回纯 priority——
     * 那等于「同一个最容易误报的牌每轮都还会被先派出去」。
     */
    credit?: {
      enabled?: boolean
      /** 探索权重。0 = 纯利用（会早熟，不推荐）。 */
      exploreWeight?: number
      /** 战绩半衰期（毫秒）。0 = 不衰减（三年前的战绩和昨天一样重）。 */
      halfLifeMs?: number
    }
  }
}

export interface ResolvedConfig {
  allowedHosts: readonly string[]
  maxToolCalls: number | undefined
  maxWallClockMs: number | undefined
  maxSteps: number | undefined
  logDecisions: boolean
  deniedTools: readonly string[]
  provenance: { enabled: boolean; strict: boolean; store: string | undefined }
  fallback: { routes: readonly { provider: string; model: string }[]; maxSwitches: number }
  hitl: {
    enabled: boolean
    allowlist: readonly string[]
    requireApproval: readonly ('read' | 'write' | 'destructive' | 'c2')[]
  }
  egress: { enabled: boolean; socketPath: string }
  queue: {
    enabled: boolean
    file: string
    evidenceRoot: string
    concurrency: number
    timeoutMs: number
    requeueInterrupted: boolean
  }
  agentDispatch: {
    enabled: boolean
    maxAttempts: number
    overallTimeoutMs: number
    costBudget: number
    stopOnInconclusive: boolean
    faultCircuit: number
  }
  timeCredit: {
    enabled: boolean
    baseMs: number
    grantMs: number
    maxMs: number
    grantCooldownMs: number
    warnAtMs: number
    debitMs: number
    maxDebitMs: number
    debitCooldownMs: number
  }
  mcp: {
    enabled: boolean
    command: readonly string[]
    cwd: string | undefined
    timeoutMs: number
  }
  artex: {
    enabled: boolean
    baseUrl: string
    password: string
  }
  council: {
    enabled: boolean
    credit: { enabled: boolean; exploreWeight: number; halfLifeMs: number }
    rateWindowMs: number
    rateMaxPerWindow: number
    breakerThreshold: number
    breakerCooldownMs: number
    allowedHosts: readonly string[]
  }
}

function assertPositiveInt(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`secops: config field "${field}" must be a positive safe integer, got ${String(value)}`)
  }
  return value
}

/** 非负有限数（允许 0）。权重类字段用它，别用 assertPositiveInt 把 0 挡住。 */
function assertNonNegative(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`secops: config field "${field}" must be a non-negative finite number, got ${String(value)}`)
  }
  return value
}

export function resolveConfig(config: SecopsConfig | undefined): ResolvedConfig {
  if (config !== undefined && (typeof config !== 'object' || config === null)) {
    throw new TypeError('secops: config must be an object when present')
  }
  const input = config ?? {}

  const rawHosts = input.allowedHosts
  if (rawHosts !== undefined && !Array.isArray(rawHosts)) {
    throw new TypeError('secops: config field "allowedHosts" must be an array of strings')
  }
  const allowedHosts = (rawHosts ?? []).map((host) => {
    if (typeof host !== 'string' || host.trim().length === 0) {
      throw new TypeError('secops: config field "allowedHosts" must contain non-empty strings')
    }
    return host.trim().toLowerCase()
  })

  const logDecisions = input.logDecisions
  if (logDecisions !== undefined && typeof logDecisions !== 'boolean') {
    throw new TypeError('secops: config field "logDecisions" must be a boolean')
  }

  const q = input.queue ?? {}
  const baseDir = process.cwd()

  return {
    allowedHosts: Object.freeze([...new Set(allowedHosts)]),
    maxToolCalls: assertPositiveInt(input.maxToolCalls, 'maxToolCalls'),
    maxWallClockMs: assertPositiveInt(input.maxWallClockMs, 'maxWallClockMs'),
    maxSteps: assertPositiveInt(input.maxSteps, 'maxSteps'),
    logDecisions: logDecisions ?? true,
    deniedTools: Object.freeze((input.deniedTools ?? []).filter((t): t is string => typeof t === 'string' && t.length > 0)),
    hitl: {
      enabled: input.hitl?.enabled ?? false,
      allowlist: Object.freeze([...(input.hitl?.allowlist ?? [])]),
      requireApproval: Object.freeze([...(input.hitl?.requireApproval ?? ['write', 'destructive', 'c2'])]),
    },
    fallback: {
      routes: Object.freeze(
        (input.fallback?.routes ?? [])
          .filter((r) => typeof r?.provider === 'string' && r.provider.length > 0 && typeof r?.model === 'string' && r.model.length > 0)
          .map((r) => Object.freeze({ provider: r.provider, model: r.model })),
      ),
      maxSwitches: Math.max(0, input.fallback?.maxSwitches ?? 3),
    },
    provenance: {
      enabled: input.provenance?.enabled ?? true,
      strict: input.provenance?.strict ?? true,
      store: input.provenance?.store,
    },
    egress: {
      enabled: input.egress?.enabled ?? false,
      socketPath: input.egress?.socketPath ?? `${baseDir}/.dsh-secops/egress.sock`,
    },
    queue: {
      enabled: q.enabled ?? false,
      file: q.file ?? `${baseDir}/.dsh-secops/queue.jsonl`,
      evidenceRoot: q.evidenceRoot ?? `${baseDir}/.dsh-secops/evidence`,
      concurrency: Math.max(1, q.concurrency ?? 2),
      timeoutMs: Math.max(1, q.timeoutMs ?? 120_000),
      requeueInterrupted: q.requeueInterrupted ?? false,
    },
    agentDispatch: {
      // 默认跟随 queue：agent 调度复用队列的执行器和证据目录，
      // 队列不开就无处落证据，这时开着调度只会产出没有证据的结论。
      enabled: input.agentDispatch?.enabled ?? (q.enabled ?? false),
      maxAttempts: assertPositiveInt(input.agentDispatch?.maxAttempts, 'agentDispatch.maxAttempts') ?? 2,
      overallTimeoutMs: assertPositiveInt(input.agentDispatch?.overallTimeoutMs, 'agentDispatch.overallTimeoutMs') ?? 300_000,
      costBudget: assertPositiveInt(input.agentDispatch?.costBudget, 'agentDispatch.costBudget') ?? 10,
      stopOnInconclusive: input.agentDispatch?.stopOnInconclusive ?? true,
      faultCircuit: assertPositiveInt(input.agentDispatch?.faultCircuit, 'agentDispatch.faultCircuit') ?? 2,
    },
    timeCredit: {
      enabled: input.timeCredit?.enabled ?? false,
      baseMs: assertPositiveInt(input.timeCredit?.baseMs, 'timeCredit.baseMs') ?? 30 * 60 * 1000,
      grantMs: assertPositiveInt(input.timeCredit?.grantMs, 'timeCredit.grantMs') ?? 10 * 60 * 1000,
      maxMs: assertPositiveInt(input.timeCredit?.maxMs, 'timeCredit.maxMs') ?? 120 * 60 * 1000,
      grantCooldownMs: assertPositiveInt(input.timeCredit?.grantCooldownMs, 'timeCredit.grantCooldownMs') ?? 2 * 60 * 1000,
      warnAtMs: assertPositiveInt(input.timeCredit?.warnAtMs, 'timeCredit.warnAtMs') ?? 5 * 60 * 1000,
      debitMs: assertPositiveInt(input.timeCredit?.debitMs, 'timeCredit.debitMs') ?? 5 * 60 * 1000,
      maxDebitMs: assertNonNegative(input.timeCredit?.maxDebitMs, 'timeCredit.maxDebitMs') ?? 15 * 60 * 1000,
      debitCooldownMs: assertPositiveInt(input.timeCredit?.debitCooldownMs, 'timeCredit.debitCooldownMs') ?? 5 * 60 * 1000,
    },
    mcp: {
      enabled: input.mcp?.enabled ?? false,
      command: Object.freeze((input.mcp?.command ?? []).filter((c): c is string => typeof c === 'string' && c.length > 0)),
      cwd: input.mcp?.cwd,
      timeoutMs: assertPositiveInt(input.mcp?.timeoutMs, 'mcp.timeoutMs') ?? 30_000,
    },
    artex: {
      enabled: input.artex?.enabled ?? false,
      baseUrl: (input.artex?.baseUrl ?? 'http://127.0.0.1:8787').replace(/\/+$/, ''),
      password: input.artex?.password ?? '',
    },
    council: {
      enabled: input.council?.enabled ?? (q.enabled ?? false),
      credit: {
        enabled: input.council?.credit?.enabled ?? true,
        // 0.15 是实测量级：总执行 100 次时，没跑过的牌拿 +0.32 的探索分，
        // 刚好让它排在「成功过几次」后面、排在「失手过」前面。设更大（0.5）
        // 会让没跑过的牌永远盖住已验证的好牌；设 0 则早熟，一旦某牌领先就再不换人。
        exploreWeight: assertNonNegative(input.council?.credit?.exploreWeight, 'council.credit.exploreWeight') ?? 0.15,
        // 90 天：一次渗透周期内基本不衰减，跨季度开始淡出。
        halfLifeMs: assertNonNegative(input.council?.credit?.halfLifeMs, 'council.credit.halfLifeMs') ?? 90 * 24 * 60 * 60 * 1000,
      },
      rateWindowMs: assertPositiveInt(input.council?.rateWindowMs, 'council.rateWindowMs') ?? 60_000,
      rateMaxPerWindow: assertPositiveInt(input.council?.rateMaxPerWindow, 'council.rateMaxPerWindow') ?? 6,
      breakerThreshold: assertPositiveInt(input.council?.breakerThreshold, 'council.breakerThreshold') ?? 3,
      breakerCooldownMs: assertPositiveInt(input.council?.breakerCooldownMs, 'council.breakerCooldownMs') ?? 120_000,
      allowedHosts: Object.freeze((input.council?.allowedHosts ?? []).filter((h) => typeof h === 'string' && h.length > 0)),
    },
  }
}
