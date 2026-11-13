/**
 * 方向级调度器：同方向多候选，按适配度选一个，坏了才换，该停就停。
 *
 * 三个判断，缺一个就会变成「一路跑到底」：
 *
 *   1. 派谁 —— 按目标形态算适配度，corvus 吃 MCP 启动命令、mcp-scan 吃配置文件，
 *      给错了就算跑起来也是白烧一次。适配度优先于固定优先级。
 *
 *   2. 何时换 —— 只有 agent 自身故障才自动换。工具坏了是机械替换，不需要判断；
 *      而「跑通了但没有定论」需要判断，交回主控决定，不自动烧第二个。
 *
 *   3. 何时停 —— 代价预算、同类故障熔断、形态不匹配、墙钟，四条独立的止损线。
 *      只靠 maxAttempts 计数是不够的：五次便宜的静态检查和一个会烧 LLM 额度的
 *      扫描器，在同一个计数器下平权，那等于用预算买噪音。
 */

import path from 'node:path'
import { detectTargetShape } from './agent-registry.ts'
import type { AgentCandidate, AgentRegistry, CostTier, Direction, TargetShape } from './agent-registry.ts'
import { COST_WEIGHT, fitness } from './agent-registry.ts'

/** 单次尝试的结果。执行层负责把进程现象翻译成这四种之一。 */
export type AttemptResult =
  | {
      readonly kind: 'completed'
      readonly found: boolean
      readonly detail?: string
      /** 结论强弱：finding 可直接利用 / exposure 暴露面 / clean 干净。 */
      readonly findingClass?: 'finding' | 'exposure' | 'clean'
    }
  | { readonly kind: 'agent-failure'; readonly reason: string }
  | { readonly kind: 'inconclusive'; readonly reason: string }
  | { readonly kind: 'refused'; readonly reason: string }

/**
 * 停手原因。
 *
 * 每一项都要能回答「为什么不再试下一个」，否则这个字段没有意义——
 * 模型和人都需要知道是「没得选」「不值得」还是「再试也一样」。
 */
export type StopReason =
  /** 拿到终态结论。 */
  | 'settled'
  /** 该方向再没有可用候选（全缺失 / 全冷却 / 已试遍）。 */
  | 'exhausted'
  /** 剩余候选都明确声明不接受这个目标形态。 */
  | 'no-fit'
  /** 累计代价触顶。 */
  | 'cost-budget'
  /** 墙钟触顶。 */
  | 'deadline'
  /** 连续同类故障：再换一个大概率同样结果。 */
  | 'fault-circuit'
  /** 跑通了但没有定论，按策略交回主控。 */
  | 'inconclusive'
  /** 达到尝试次数上限。 */
  | 'max-attempts'
  /** 调用方中止。 */
  | 'aborted'

/** 一次尝试的审计记录。 */
export interface AttemptRecord {
  readonly agentId: string
  readonly direction: Direction
  readonly result: AttemptResult['kind']
  readonly reason?: string
  readonly detail?: string
  /** 该 agent 拼出的完整 argv（cli 类才有）。 */
  readonly argv?: readonly string[]
  /** 本次尝试的证据目录（stdout/stderr/meta/agent 报告都在这里）。 */
  readonly evidenceDir: string
  /** 派出去时对目标形态的适配度，用来复核「为什么是这个 agent」。 */
  readonly fitness: number
  readonly cost: CostTier
}

/** 调度终态。 */
export interface DispatchOutcome {
  /** 真正给出终态结论的 agent；没结论时为 undefined。 */
  readonly by?: string
  /** 是否跑到了终态（有结论）。 */
  readonly settled: boolean
  /** 终态结论是否"有发现"。settled=false 时无意义。 */
  readonly found: boolean
  /** 结论强弱；undefined 表示这次没有分档信息。 */
  readonly findingClass?: 'finding' | 'exposure' | 'clean'
  /** 终态结论附带的摘要。 */
  readonly detail?: string
  /** 尝试链，按时间顺序。 */
  readonly attempts: readonly AttemptRecord[]
  /** 最后一条失败/未定原因。 */
  readonly failureReason?: string
  /** 为什么停在这里。 */
  readonly stopReason: StopReason
  /** 判定出来的目标形态。 */
  readonly shape: TargetShape
  /** 累计花掉的代价权重。 */
  readonly costSpent: number
  /**
   * 声明了 claim 且执行层确实建立了关联。
   *
   * 这个字段存在的理由是一次真实故障：link 被传到了工具层而不是执行层，
   * 工具照常报 settled=true，而 claim 永远拿不到证据，两边都没有任何提示。
   * 静默不生效比直接报错危险得多——所以把「有没有真的链上」变成返回字段。
   */
  readonly claimLinked: boolean
  /** 停手时该方向还剩哪些候选没试，附各自适配度。 */
  readonly untried?: readonly { readonly agent: string; readonly fitness: number }[]
}

/** 每次尝试附带的上下文（跨轮次不变）。 */
export interface AttemptMeta {
  /** 该派活归属的 claim。执行层据此把产物归档成证据。 */
  readonly claimId?: string
  /**
   * 本次派活的目标形态。
   *
   * 往下传是为了让 claim 记住「这条断言是在哪种形态下产生的」，
   * 信誉才能按形态分层。它不影响执行本身，只影响事后怎么记账。
   */
  readonly shape?: TargetShape
}

/** 执行一次尝试。生产实现走 QueueRunner，测试注入假实现。 */
export type AttemptFn = (
  candidate: AgentCandidate,
  arg: ArgBuilderResult,
  signal: AbortSignal,
  meta: AttemptMeta,
) => Promise<AttemptResult>

/** 任务参数如何落到候选 agent 上。 */
export interface DispatchRequest {
  readonly direction: Direction
  /** 传给 agent 的目标：URL / MCP 启动命令 / 目录 / 配置文件路径。 */
  readonly target: string
  /** 单个 agent 的超时。 */
  readonly timeoutMs?: number
  /** 最多尝试几个 agent。 */
  readonly maxAttempts?: number
  /** 归属的 claim。声明后每次尝试的产物都会进证据体系。 */
  readonly claimId?: string
  /** 要第二意见：允许在「跑通但没定论」时继续换下一个。 */
  readonly secondOpinion?: boolean
  /** 优先派给这个 agent（太尉分配的结果）。不适配或不可用时忽略。 */
  readonly preferAgentId?: string
  /**
   * 覆盖本轮的整体截止时间。
   *
   * 存在的理由：一个方向里可能同时有 84 秒的牌和 27 分钟的牌。用一个固定的
   * 整体超时，要么把慢牌永远砍在半路，要么为了慢牌把快牌的安全网放到形同虚设。
   * 调用方按「本方向最慢候选」算一个上限传进来。
   */
  readonly deadlineMs?: number
}

export interface ArgBuilderResult {
  readonly argv: readonly string[]
  readonly timeoutMs: number
  /** 候选未声明 invocation（例如 subagent 类）时为 false。 */
  readonly supported: boolean
  /** 本次尝试的任务 id，同时是证据目录名。 */
  readonly taskId: string
  /** 本次尝试专属的证据目录。 */
  readonly evidenceDir: string
}

/**
 * 停手策略。
 *
 * 默认值刻意保守：一次主力 + 一次兜底，5 分钟，权重 10。
 * 保守的默认值让「想跑更多」变成一个显式动作，而不是默认行为——
 * 默认狂试的系统，其输出没人会认真看。
 */
export interface DispatchPolicy {
  readonly maxAttempts: number
  readonly deadlineMs: number
  /** 累计代价权重上限。cheap=1 / moderate=3 / expensive=10。 */
  readonly costBudget: number
  /** 跑通但没定论时是否自动换下一个。默认 false。 */
  readonly stopOnInconclusive: boolean
  /** 同一类故障连续出现几次就熔断。默认 2。 */
  readonly faultCircuit: number
}

export const DEFAULT_POLICY: DispatchPolicy = {
  maxAttempts: 2,
  deadlineMs: 5 * 60 * 1000,
  costBudget: 10,
  // 默认停手：跑通但没定论时不再自动烧第二个。
  // 库默认与工程配置必须一致——两边不一致时，测试通过而线上白烧钱，最难查。
  stopOnInconclusive: true,
  faultCircuit: 2,
}

export interface DispatcherOptions {
  readonly registry: AgentRegistry
  readonly attempt: AttemptFn
  /** 证据根目录，每次尝试在其中建一个子目录。 */
  readonly evidenceRoot: string
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
  readonly maxAttempts?: number
  /** 执行层是否会在 submit 前把任务关联到 claim。 */
  readonly supportsClaim?: boolean
  /** 覆盖默认策略的部分字段。 */
  readonly policy?: Partial<DispatchPolicy>
  /** 目标形态探测，测试可注入。 */
  readonly detectShape?: (target: string) => TargetShape
  /**
   * 信誉来源（0..1）。同方向同适配度的候选按它排序。
   *
   * 只影响「先试谁」，不影响「能不能试」：适配度是硬条件，信誉是软偏好。
   * 一张信誉再高的牌，吃不下这个形态也照样排除。
   */
  readonly creditOf?: (agentId: string, shape?: TargetShape) => number | undefined
}

const DEFAULT_TIMEOUT_MS = 120_000

function safeSegment(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40)
}

/**
 * 把候选的命令前缀、目标、以及候选自己声明的固定参数拼成 argv。
 *
 * 只做数组拼接，永远不拼字符串——一旦拼字符串就会出现参数注入：
 * 目标里带个空格或分号就能变成另一个参数或第二条命令。
 */
export function buildArgv(
  candidate: AgentCandidate,
  target: string,
  attemptIndex: number,
  options: { readonly evidenceRoot: string; readonly timeoutMs?: number },
): ArgBuilderResult {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  // 每次尝试独立目录：上一次的残留报告绝不能被下一次的 verdict 读到，
  // 否则"上一轮扫出了发现"会被误记成本轮结论。
  const taskId = `${safeSegment(candidate.direction)}-${safeSegment(candidate.id)}-${attemptIndex}-${Date.now().toString(36)}`
  const evidenceDir = path.join(options.evidenceRoot, taskId)
  const prefix = candidate.command ?? []
  if (candidate.invocation === undefined) {
    return { argv: prefix, timeoutMs, supported: false, taskId, evidenceDir }
  }
  return {
    argv: [...prefix, ...candidate.invocation(target, { evidenceDir })],
    timeoutMs,
    supported: true,
    taskId,
    evidenceDir,
  }
}

/** 把失败原因归一成类别，用来判断「再试一个是不是白试」。 */
export function classifyFault(reason: string): string {
  const r = reason.toLowerCase()
  if (r.includes('not found') || r.includes('enoent')) return 'missing-binary'
  if (r.includes('timed out') || r.includes('timeout')) return 'timeout'
  if (r.includes('terminated by signal')) return 'signal'
  if (r.includes('eacces') || r.includes('not executable')) return 'permission'
  if (r.includes('spawn error')) return 'spawn'
  if (r.startsWith('exit ')) return 'nonzero-exit'
  if (r.includes('threw')) return 'executor-error'
  return 'other'
}

export class DirectionalDispatcher {
  private readonly registry: AgentRegistry
  private readonly attempt: AttemptFn
  private readonly logger: DispatcherOptions['logger']
  private readonly evidenceRoot: string
  private readonly supportsClaim: boolean
  private readonly creditOf: ((agentId: string, shape?: TargetShape) => number | undefined) | undefined
  private readonly policy: DispatchPolicy
  private readonly detectShape: (target: string) => TargetShape

  constructor(options: DispatcherOptions) {
    this.registry = options.registry
    this.creditOf = options.creditOf
    this.attempt = options.attempt
    this.logger = options.logger
    this.evidenceRoot = options.evidenceRoot
    this.supportsClaim = options.supportsClaim ?? false
    this.detectShape = options.detectShape ?? detectTargetShape
    this.policy = {
      ...DEFAULT_POLICY,
      ...(options.maxAttempts === undefined ? {} : { maxAttempts: options.maxAttempts }),
      ...(options.policy ?? {}),
    }
  }

  async dispatch(request: DispatchRequest, signal: AbortSignal): Promise<DispatchOutcome> {
    const shape = this.detectShape(request.target)
    const policy: DispatchPolicy = {
      ...this.policy,
      ...(request.maxAttempts === undefined ? {} : { maxAttempts: request.maxAttempts }),
      ...(request.secondOpinion === true ? { stopOnInconclusive: false, costBudget: this.policy.costBudget * 2 } : {}),
      ...(request.deadlineMs === undefined ? {} : { deadlineMs: request.deadlineMs }),
    }
    const deadline = Date.now() + policy.deadlineMs

    const attempts: AttemptRecord[] = []
    const tried = new Set<string>()
    const faultCounts = new Map<string, number>()
    let costSpent = 0
    let lastReason: string | undefined

    const finish = (stopReason: StopReason, extra: Partial<DispatchOutcome> = {}): DispatchOutcome => ({
      settled: false,
      found: false,
      attempts,
      shape,
      costSpent,
      stopReason,
      claimLinked: this.claimLinkedFor(request),
      ...this.untriedOf(request.direction, shape, tried),
      ...(lastReason === undefined ? {} : { failureReason: lastReason }),
      ...extra,
    })

    for (;;) {
      if (signal.aborted) return finish('aborted')
      if (Date.now() > deadline) {
        this.logger?.warn(`dispatch: deadline reached after ${attempts.length} attempt(s)`)
        return finish('deadline')
      }
      if (attempts.length >= policy.maxAttempts) return finish('max-attempts')

      const pool = this.registry
        .available(request.direction, shape, this.creditOf === undefined ? {} : { creditOf: this.creditOf })
        .filter((c) => !tried.has(c.id))
      if (pool.length === 0) return finish('exhausted')

      // 形态全不匹配就不要再跑：这些 agent 明确声明吃不下这类输入，
      // 派出去的结果一定是失败，只是把时间花在证明一件已知的事上。
      if (pool.every((c) => fitness(c, shape) === 0)) {
        this.logger?.warn(`dispatch: no candidate accepts target shape "${shape}" in ${request.direction}`)
        return finish('no-fit')
      }

      // 太尉指定了首选就照办，但只在它真的能吃这个形态时才照办——
      // 分配信息不该覆盖适配度判断，那是两件事。
      const preferred =
        request.preferAgentId === undefined
          ? undefined
          : pool.find((c) => c.id === request.preferAgentId && fitness(c, shape) > 0)
      const candidate = preferred ?? pool.find((c) => fitness(c, shape) > 0) ?? pool[0]!
      const fit = fitness(candidate, shape)
      const cost = candidate.cost ?? 'moderate'
      const weight = COST_WEIGHT[cost]

      if (costSpent + weight > policy.costBudget) {
        this.logger?.warn(`dispatch: cost budget exhausted (${costSpent}+${weight} > ${policy.costBudget}); not running ${candidate.id}`)
        return finish('cost-budget')
      }

      tried.add(candidate.id)
      costSpent += weight

      const timeoutMs = request.timeoutMs ?? candidate.defaultTimeoutMs
      const arg = buildArgv(candidate, request.target, attempts.length, {
        evidenceRoot: this.evidenceRoot,
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      })
      this.logger?.info(
        `dispatch: ${request.direction}/${shape} → ${candidate.id} (fitness=${fit}, cost=${cost}${arg.supported ? '' : ', unsupported'})`,
      )

      let result: AttemptResult
      if (!arg.supported) {
        result = { kind: 'refused', reason: 'execution layer does not drive this agent kind' }
      } else {
        try {
          result = await this.attempt(candidate, arg, signal, {
            ...(request.claimId === undefined ? {} : { claimId: request.claimId }),
            shape,
          })
        } catch (err) {
          result = { kind: 'agent-failure', reason: `attempt threw: ${(err as Error).message}` }
        }
      }

      attempts.push({
        agentId: candidate.id,
        direction: request.direction,
        result: result.kind,
        ...(result.kind === 'completed'
          ? result.detail === undefined
            ? {}
            : { detail: result.detail }
          : { reason: result.reason }),
        ...(candidate.kind === 'cli' && arg.supported ? { argv: arg.argv } : {}),
        evidenceDir: arg.evidenceDir,
        fitness: fit,
        cost,
      })

      switch (result.kind) {
        case 'completed':
          this.registry.reportSuccess(candidate.id)
          return {
            by: candidate.id,
            settled: true,
            found: result.found,
            ...(result.findingClass === undefined ? {} : { findingClass: result.findingClass }),
            attempts,
            shape,
            costSpent,
            stopReason: 'settled',
            claimLinked: this.claimLinkedFor(request),
            ...(result.detail === undefined ? {} : { detail: result.detail }),
            ...this.untriedOf(request.direction, shape, tried),
          }

        case 'agent-failure': {
          this.registry.reportFailure(candidate.id)
          lastReason = result.reason
          const fault = classifyFault(result.reason)
          const seen = (faultCounts.get(fault) ?? 0) + 1
          faultCounts.set(fault, seen)
          if (seen >= policy.faultCircuit) {
            // 同一类故障重复出现，说明问题不在 agent 而在更外层（目标、网络、环境）。
            // 继续换只是把同一个失败重演一遍。
            this.logger?.warn(`dispatch: circuit open on "${fault}" (${seen} consecutive) — stopping`)
            return finish('fault-circuit')
          }
          break
        }

        case 'refused':
          lastReason = result.reason
          break

        case 'inconclusive':
          lastReason = result.reason
          if (policy.stopOnInconclusive) {
            // 跑通了但没定论：这不是 agent 的错，是信息不足。
            // 继续换等于用第二个工具的偶然差异赌一个结论，交回主控更诚实。
            return finish('inconclusive')
          }
          break
      }
    }
  }

  private claimLinkedFor(request: DispatchRequest): boolean {
    return request.claimId !== undefined && this.supportsClaim
  }

  private untriedOf(
    direction: Direction,
    shape: TargetShape,
    tried: Set<string>,
  ): { untried: { agent: string; fitness: number }[] } {
    const rest = this.registry
      .available(direction, shape, this.creditOf === undefined ? {} : { creditOf: this.creditOf })
      .filter((c) => !tried.has(c.id))
      .map((c) => ({ agent: c.id, fitness: fitness(c, shape) }))
    // 全部试完时不返回这个字段，避免在成功结果里塞一个空数组噪音
    return rest.length === 0 ? ({} as { untried: { agent: string; fitness: number }[] }) : { untried: rest }
  }
}

/**
 * 把进程现象翻译成 AttemptResult。
 *
 * 判定依据只有执行层能拿到的事实：退出码、是否超时、stderr 特征、
 * 以及 agent 约定的输出结构。绝不能靠猜——"输出里没出现 'vulnerable' 字样"
 * 不构成 no-finding 证据。
 */
/**
 * 环境不满足的特征串。
 *
 * 只认**机器可读的错误码**，不认自然语言措辞——「error」「failed」这类
 * 词在任何工具里都出现，拿它们判拒绝会把真正的失败说成环境问题。
 * 这里的每个码都被具体工具真正输出过（rea 的 provider_unavailable /
 * unsupported_version 来自 ghidra 12.2 与 rea 要求的 12.1.x 不匹配）。
 */
const ENV_UNFIT: ReadonlyArray<{ readonly re: RegExp; readonly label: string }> = [
  { re: /\bprovider_unavailable\b/, label: 'analysis provider unavailable' },
  { re: /\bunsupported_version\b/, label: 'engine version unsupported' },
  { re: /\bmissing_analysis_engine\b|\bengine_not_found\b/, label: 'analysis engine missing' },
  { re: /\bnot_configured\b/, label: 'required dependency not configured' },
]

/** 返回拒绝原因；没命中返回 undefined。 */
export function detectEnvUnfit(stdout: string | undefined, stderr: string): string | undefined {
  const text = `${stdout ?? ''}\n${stderr}`
  for (const { re, label } of ENV_UNFIT) {
    const m = re.exec(text)
    if (m === null) continue
    // 抓命中行，让 reason 能被人直接核对，而不是只给一个标签。
    const line = text
      .split('\n')
      .find((l) => re.test(l))
      ?.trim()
      .slice(0, 160)
    return `refused: ${label}${line === undefined || line === '' ? '' : ` — ${line}`}`
  }
  return undefined
}

export function classifyProcess(input: {
  readonly exitCode: number | null
  readonly timedOut: boolean
  readonly stderr: string
  readonly spawnError?: NodeJS.ErrnoException
  /** agent 的 stdout。用来识别「跑起来了但环境不满足」这类拒绝。 */
  readonly stdout?: string
  /** agent 输出里被解析出的结构化终态；undefined 表示没有结构化输出。 */
  readonly structured?: { readonly found: boolean; readonly class?: 'finding' | 'exposure' | 'clean' }
}): AttemptResult {
  if (input.spawnError !== undefined) {
    const code = input.spawnError.code
    if (code === 'ENOENT') {
      return { kind: 'agent-failure', reason: 'executable not found (ENOENT)' }
    }
    if (code === 'EACCES') {
      return { kind: 'agent-failure', reason: 'executable not executable (EACCES)' }
    }
    return { kind: 'agent-failure', reason: `spawn error: ${code ?? input.spawnError.message}` }
  }
  if (input.timedOut) {
    return { kind: 'agent-failure', reason: 'timed out' }
  }
  // 崩溃类信号在 POSIX 下体现为 null exitCode
  if (input.exitCode === null) {
    return { kind: 'agent-failure', reason: 'terminated by signal' }
  }
  if (input.structured !== undefined) {
    return {
      kind: 'completed',
      found: input.structured.found,
      ...(input.structured.class === undefined ? {} : { findingClass: input.structured.class }),
    }
  }
  // 跑起来了、但不是因为目标而是因为**本机环境不满足**而拒绝干活。
  // 这类失败重试和换目标都不会变，而且不是 agent 的过错——把它计进
  // agent-failure 会让误报账记错人，还会在熔断计数里堆出假信号。
  // 典型：rea 装了但 Ghidra 版本不兼容，报 provider_unavailable / unsupported_version。
  const unfit = detectEnvUnfit(input.stdout, input.stderr)
  if (unfit !== undefined) return { kind: 'refused', reason: unfit }

  if (input.exitCode === 0) {
    // 退出码 0 但没有结构化输出：跑通了，结论不明。
    // 这里最容易被写错成 found=true 或 found=false，两者都是编造。
    return { kind: 'inconclusive', reason: 'exit 0 without structured verdict' }
  }
  if (input.exitCode === 2 || /usage:|unknown (option|argument)|invalid argument/i.test(input.stderr)) {
    return { kind: 'refused', reason: `agent rejected invocation (exit ${input.exitCode})` }
  }
  return {
    kind: 'agent-failure',
    reason: `exit ${input.exitCode}${input.stderr.trim() === '' ? '' : `: ${firstLine(input.stderr)}`}`,
  }
}

function firstLine(s: string): string {
  return (s.trim().split('\n')[0] ?? '').slice(0, 200)
}
