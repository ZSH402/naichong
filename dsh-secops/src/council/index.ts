/**
 * 三公：丞相（分析）、太尉（调度）、御史大夫（风控）。
 *
 * 这是**职责划分**，不是三个模型。三者的判断依据都是结构化的：
 * 丞相看断言与缺口，太尉看方向与候选，御史看账本与熔断状态。
 * 需要语义的部分（这个目标可能有什么问题）留给会话里的主模型。
 *
 * 为什么不让模型当三公：预算是算出来的，不是聊出来的。一个会算错余额的
 * 御史大夫，比没有御史大夫更糟——它会让「已批准」失去含义。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { JsonSchemaNode, ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { AgentRegistry, Direction } from '../agent-registry.ts'
import type { DirectionalDispatcher } from '../agent-dispatch.ts'
import type { ClaimStore } from '../provenance-tools.ts'
import { Censor } from './censor.ts'
import type { CensorPolicy, LedgerView } from './censor.ts'
import { Chancellor } from './chancellor.ts'
import type { Assessment, Hypothesis, KnowledgeSource } from './chancellor.ts'
import { Marshal } from './marshal.ts'
import type { BoardEntry, MarshalPlan, MarshalSummary } from './marshal.ts'
import { Roster } from './roster.ts'
import { analyzePrecision, precisionActions } from './precision.ts'
import type { PrecisionReport } from './precision.ts'
import type { CreditScore } from './credit.ts'
import type { AgentRecord } from './roster.ts'
import { AdapterRegistry } from './contract.ts'
import type { TaskKind } from './contract.ts'
import { createAgentAdapter, createCliToolAdapter } from './adapters.ts'

export { Censor, CENSOR_DEFAULTS } from './censor.ts'
export { Chancellor } from './chancellor.ts'
export { Marshal } from './marshal.ts'
export { Roster } from './roster.ts'
export { analyzePrecision, precisionActions, agentsOfClaim, MIN_SAMPLE } from './precision.ts'
export type { AgentPrecision, PrecisionReport } from './precision.ts'
export * from './contract.ts'
export * from './adapters.ts'
export type { Assessment, Hypothesis, MarshalPlan, MarshalSummary, BoardEntry, AgentRecord, LedgerView }

export interface CouncilDeps {
  readonly registry: AgentRegistry
  readonly dispatcher: DirectionalDispatcher
  readonly claims: ClaimStore
  readonly paths: {
    readonly roster: string
    readonly board: string
  }
  readonly censorPolicy?: Partial<CensorPolicy>
  /** 覆盖账本：太尉执行后自动落下戳，丞相分析时据此判断「什么还没测」。 */
  readonly coverage?: import('../coverage.ts').CoverageLedger
  /** 资产库：扫描结果解析成可查询的资产，供丞相和下一轮派活使用。 */
  readonly assets?: import('../asset-store.ts').AssetStore
  /** 外部 agent 执行体（例如 ARTEX）。没有时 agent kind 保持「未接通」。 */
  /**
   * 信誉账。传入后每轮编排开始前刷新一次，供 status 展示与排序使用。
   *
   * 由调用方创建并共享：dispatcher 通过闭包引用同一个实例，
   * 否则「刷新」和「排序」会各自持有一份数据，谁也看不见谁。
   */
  readonly credit?: import('./credit.ts').CreditBoard
  readonly agentAdapter?: import('./contract.ts').TaskAdapter
  /** MCP server 适配（CyberStrikeAI / rea / hexstrike）。没有时 mcp kind 不注册。 */
  readonly mcpAdapter?: import('./contract.ts').TaskAdapter
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
}

/** 把 ClaimStore 适配成丞相能读的知识源。 */
export function createKnowledgeSource(
  claims: ClaimStore,
  dispatchMemory: { last?: { direction: Direction; target: string; stopReason: string; untried?: { agent: string; fitness: number }[] } },
): KnowledgeSource {
  return {
    claims: () =>
      claims.query().map((c) => ({
        id: c.id,
        claim: c.claim,
        status: c.status,
        evidenceCount: c.evidence.length,
        independentPaths: c.independentPaths,
        ...(c.falsifier === undefined ? {} : { falsifier: c.falsifier }),
      })),
    lastDispatch: () => dispatchMemory.last,
  }
}

export class Council {
  readonly censor: Censor
  readonly chancellor: Chancellor
  readonly marshal: Marshal
  readonly roster: Roster
  readonly adapters: AdapterRegistry
  private readonly claims: ClaimStore
  private readonly credit: import('./credit.ts').CreditBoard | undefined
  private readonly dispatchMemory: {
    last?: { direction: Direction; target: string; stopReason: string; untried?: { agent: string; fitness: number }[] }
  } = {}

  constructor(deps: CouncilDeps) {
    this.censor = new Censor(deps.censorPolicy ?? {})
    this.claims = deps.claims
    this.credit = deps.credit
    this.roster = new Roster(deps.paths.roster)
    const knowledge = createKnowledgeSource(deps.claims, this.dispatchMemory)
    this.chancellor = new Chancellor({
      registry: deps.registry,
      knowledge,
      ...(deps.coverage === undefined ? {} : { coverage: deps.coverage }),
      ...(deps.assets === undefined ? {} : { assets: deps.assets }),
    })

    this.adapters = new AdapterRegistry()
    this.adapters.register(
      createCliToolAdapter({
        dispatcher: deps.dispatcher,
        registry: deps.registry,
        censorSettle: (contract, outcome) => {
          this.censor.settle(contract, outcome)
        },
      }),
    )
    if (deps.mcpAdapter !== undefined) this.adapters.register(deps.mcpAdapter)
    this.adapters.register(
      deps.agentAdapter ??
        createAgentAdapter({
          available: false,
          reason: 'subagent provider 通道未接通（当前只驱动 CLI）',
        }),
    )

    this.marshal = new Marshal({
      registry: deps.registry,
      adapters: this.adapters,
      censor: this.censor,
      boardPath: deps.paths.board,
      ...(deps.coverage === undefined ? {} : { coverage: deps.coverage }),
      ...(deps.assets === undefined ? {} : { assets: deps.assets }),
      ...(deps.logger === undefined ? {} : { logger: deps.logger }),
    })
  }

  /** 丞相：盘局面、出假设。 */
  assess(input: {
    readonly target: string
    readonly directions?: readonly Direction[]
    readonly manual?: readonly { statement: string; falsifiableBy: string; direction: Direction; priority?: 'high' | 'medium' | 'low' }[]
  }): Assessment {
    return this.chancellor.assess(input)
  }

  /** 太尉：拆解、审批、执行、汇总。 */
  async run(input: {
    readonly target: string
    readonly directions?: readonly Direction[]
    readonly manual?: readonly { statement: string; falsifiableBy: string; direction: Direction; priority?: 'high' | 'medium' | 'low' }[]
    readonly maxTasks?: number
    readonly claimId?: string
    readonly signal: AbortSignal
  }): Promise<{ plan: MarshalPlan; summary: MarshalSummary; assessment: Assessment }> {
    // 每轮先刷新信誉：上一轮的确认/推翻必须影响这一轮的排序，
    // 否则「奖惩」永远是滞后一轮的装饰。refresh 是纯计算，不落盘。
    this.credit?.refresh(this.claims.query(), this.roster)

    const assessment = this.assess({
      target: input.target,
      ...(input.directions === undefined ? {} : { directions: input.directions }),
      ...(input.manual === undefined ? {} : { manual: input.manual }),
    })
    const plan = this.marshal.plan(assessment, {
      ...(input.claimId === undefined ? {} : { claimId: input.claimId }),
      requestedBy: 'user',
    })
    const limit = Math.max(1, input.maxTasks ?? 3)
    const capped: MarshalPlan = { ...plan, tasks: plan.tasks.slice(0, limit) }
    const summary = await this.marshal.execute(capped, input.signal)

    // 把最后一轮的形状记进记忆，供下一轮丞相判断「上次没定论该换谁」
    const lastResult = summary.results[summary.results.length - 1]
    if (lastResult !== undefined) {
      this.dispatchMemory.last = {
        direction: lastResult.contract.direction,
        target: lastResult.contract.target,
        stopReason: lastResult.outcome,
        ...(lastResult.attempts === undefined
          ? {}
          : { untried: lastResult.attempts.map((a) => ({ agent: a.agent, fitness: a.fitness ?? 0 })) }),
      }
    }

    for (const r of summary.results) {
      if (r.agentId === undefined) continue
      this.roster.record({
        agentId: r.agentId,
        outcome: r.outcome,
        shape: assessment.shape,
        durationMs: r.durationMs,
        ...(r.found === undefined ? {} : { found: r.found }),
        ...(r.reason === undefined ? {} : { fault: r.reason }),
      })
    }
    this.roster.persist()

    // 误报提示跟着执行结果一起回去，而不是等人再去问一次 status。
    // 报了一个发现、这条 claim 又被推翻——这个反馈必须当轮就到达。
    const precisionReport = this.precision()
    const extra = precisionActions(precisionReport)
    const merged: MarshalSummary =
      extra.length === 0 ? summary : { ...summary, nextActions: [...summary.nextActions, ...extra] }

    return { plan: capped, summary: merged, assessment }
  }

  /** 误报账本：从现有 claim 现算，不另存一份会与真相脱节的副本。 */
  precision(): PrecisionReport {
    return analyzePrecision(this.claims.query())
  }

  status(): {
    ledger: LedgerView
    board: BoardEntry[]
    roster: AgentRecord[]
    adapters: { kind: TaskKind; describe: string }[]
    policy: CensorPolicy
    precision: PrecisionReport
    precisionActions: string[]
    credit: CreditScore[]
    creditByShape: CreditScore[]
  } {
    const report = this.precision()
    // 状态查询现算一次：调用方看到的排序依据，必须是它此刻真的会用的那份。
    this.credit?.refresh(this.claims.query(), this.roster)
    return {
      ledger: this.censor.ledger(),
      board: this.marshal.boardEntries(),
      roster: this.roster.view(),
      adapters: this.adapters.describe(),
      policy: this.censor.viewPolicy(),
      precision: report,
      precisionActions: precisionActions(report),
      credit: this.credit?.all() ?? [],
      creditByShape: this.credit?.shapeView() ?? [],
    }
  }
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

const ASSESS_SCHEMA: JsonSchemaNode = {
  type: 'object',
  properties: {
    target: { type: 'string' },
    shape: { type: 'string' },
    understanding: { type: 'string' },
    covered: { type: 'array', items: { type: 'string' } },
    blockers: { type: 'array', items: { type: 'string' } },
    skipped: { type: 'array', items: { type: 'string' }, description: 'Directions skipped because coverage shows they are already complete.' },
    hypotheses: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          statement: { type: 'string' },
          falsifiable_by: { type: 'string' },
          direction: { type: 'string' },
          priority: { type: 'string' },
          origin: { type: 'string' },
        },
        required: ['id', 'statement', 'falsifiable_by', 'direction', 'priority'],
      },
    },
  },
  required: ['target', 'shape', 'understanding', 'hypotheses'],
}

const RUN_SCHEMA: JsonSchemaNode = {
  type: 'object',
  properties: {
    target: { type: 'string' },
    planned: { type: 'number' },
    executed: { type: 'number' },
    settled: { type: 'number' },
    found: { type: 'number' },
    findings: { type: 'number', description: 'Directly exploitable.' },
    exposures: { type: 'number', description: 'Exposure / misconfiguration, not a vulnerability by itself.' },
    cleans: { type: 'number', description: 'Checked and found clean.' },
    inconclusive: { type: 'number' },
    failed: { type: 'number' },
    blocked: { type: 'number' },
    spent: { type: 'number' },
    tasks: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          task: { type: 'string' },
          direction: { type: 'string' },
          hypothesis: { type: 'string' },
          outcome: { type: 'string' },
          found: { type: 'boolean' },
          class: { type: 'string', description: 'finding | exposure | clean' },
          agent: { type: 'string' },
          reason: { type: 'string' },
          detail: { type: 'string' },
          cost: { type: 'number' },
          evidence_dir: { type: 'string' },
          manifest_digest: { type: 'string' },
        },
        required: ['task', 'direction', 'outcome'],
      },
    },
    skipped: { type: 'array', items: { type: 'string' } },
    next_actions: { type: 'array', items: { type: 'string' } },
  },
  required: ['target', 'planned', 'executed', 'next_actions'],
}

const STATUS_SCHEMA: JsonSchemaNode = {
  type: 'object',
  properties: {
    credit_by_shape: {
      type: 'array',
      description:
        'Same reward/penalty ledger, scoped per (agent, target shape) — key looks like "agent@shape". Only shapes ' +
        'with enough settled claims appear; thin shapes fall back to the global score. A global score averages ' +
        'away real differences: an agent can be reliable on url targets and useless on directory targets, and ' +
        'the average would describe neither.',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string', description: 'agent@shape' },
          value: { type: 'number' },
          confirmed: { type: 'number' },
          refuted: { type: 'number' },
          basis: { type: 'string' },
        },
        required: ['key', 'value'],
      },
    },
    credit: {
      type: 'array',
      description:
        'Reward/penalty ledger. value is what candidate ordering actually uses (Beta posterior + exploration ' +
        'bonus); higher sorts earlier. posterior reflects how often its findings survived (confirmed vs refuted), ' +
        'explore keeps rarely-used agents in play. Old verdicts decay (half-life applies), so stale history ' +
        'cannot pin an agent in place forever. A low value demotes an agent but never removes it.',
      items: {
        type: 'object',
        properties: {
          agent: { type: 'string' },
          value: { type: 'number', description: '0..1, used for ordering.' },
          posterior: { type: 'number', description: 'Beta(1+confirmed, 1+refuted) mean — accuracy only.' },
          explore: { type: 'number', description: 'UCB bonus for agents with few runs.' },
          confirmed: { type: 'number' },
          refuted: { type: 'number' },
          sample: { type: 'number' },
          runs: { type: 'number' },
          basis: { type: 'string', description: 'Human-readable reason for this score.' },
        },
        required: ['agent', 'value'],
      },
    },
    limits: {
      type: 'object',
      properties: {
        rate_window_s: { type: 'number' },
        rate_max_per_window: { type: 'number' },
        breaker_threshold: { type: 'number' },
        max_task_timeout_ms: { type: 'number' },
        scope: { type: 'string', description: 'unrestricted, or the authorized host list.' },
      },
      required: ['rate_max_per_window', 'breaker_threshold', 'scope'],
    },
    runs: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          direction: { type: 'string' },
          runs: { type: 'number' },
          faults: { type: 'number' },
          in_window: { type: 'number' },
        },
        required: ['direction', 'runs'],
      },
    },
    blocked: {
      type: 'array',
      items: {
        type: 'object',
        properties: { code: { type: 'string' }, count: { type: 'number' } },
        required: ['code', 'count'],
      },
    },
    open_breakers: { type: 'array', items: { type: 'string' } },
    board: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          task: { type: 'string' },
          direction: { type: 'string' },
          status: { type: 'string' },
          outcome: { type: 'string' },
          cost: { type: 'number' },
          note: { type: 'string' },
        },
        required: ['task', 'direction', 'status'],
      },
    },
    roster: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          agent: { type: 'string' },
          runs: { type: 'number' },
          settled: { type: 'number' },
          inconclusive: { type: 'number' },
          failed: { type: 'number' },
          found: { type: 'number' },
          last_outcome: { type: 'string' },
          last_fault: { type: 'string' },
        },
        required: ['agent', 'runs'],
      },
    },
    adapters: {
      type: 'array',
      items: {
        type: 'object',
        properties: { kind: { type: 'string' }, describe: { type: 'string' } },
        required: ['kind', 'describe'],
      },
    },
    precision: {
      type: 'array',
      description: 'Per-agent false-positive ledger, computed from claims that reached a verdict.',
      items: {
        type: 'object',
        properties: {
          agent: { type: 'string' },
          reported: { type: 'number' },
          confirmed: { type: 'number' },
          refuted: { type: 'number' },
          open: { type: 'number' },
          sample: { type: 'number' },
          false_positive_rate: { type: 'number' },
          note: { type: 'string' },
        },
        required: ['agent', 'reported', 'confirmed', 'refuted', 'open', 'sample'],
      },
    },
    unattributed_refutations: { type: 'number', description: 'Refuted claims with no blame recorded — real misses the ledger cannot see.' },
    precision_actions: { type: 'array', items: { type: 'string' } },
  },
  required: ['limits', 'board', 'roster', 'adapters', 'precision'],
}

export function councilTools(council: Council): ToolDefinition[] {
  const assess: ToolDefinition = {
    name: 'council_assess',
    description:
      '丞相（分析）：盘一遍当前局面，给出可验证假设清单。依据是结构而不是猜测——' +
      '哪些方向有能吃该目标形态的可用 agent 但从没跑过、哪些断言只有一条独立路径、' +
      '上次派活卡在哪里。每条假设都必须带 falsifiable_by，写不出来就不该提。不花预算。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'URL / 主机 / 目录 / 文件 / MCP 启动命令。' },
        directions: { type: 'array', items: { type: 'string' }, description: 'Optional: restrict to these directions.' },
        manual_hypotheses: {
          type: 'array',
          description: '你自己想到的假设，直接纳入评估。每条必须给 falsifiable_by。',
          items: {
            type: 'object',
            properties: {
              statement: { type: 'string' },
              falsifiable_by: { type: 'string' },
              direction: { type: 'string' },
              priority: { type: 'string' },
            },
            required: ['statement', 'falsifiable_by', 'direction'],
          },
        },
      },
      required: ['target'],
    },
    output: {
      schema: ASSESS_SCHEMA,
      render: (_a: unknown, v: unknown) => [{ type: 'text', text: renderAssessment(v as Record<string, unknown>) }],
    },
    async execute(args: Record<string, unknown>) {
      const manual = Array.isArray(args.manual_hypotheses)
        ? (args.manual_hypotheses as Record<string, unknown>[])
            .filter((m) => typeof m.statement === 'string' && typeof m.falsifiable_by === 'string' && typeof m.direction === 'string')
            .map((m) => ({
              statement: String(m.statement),
              falsifiableBy: String(m.falsifiable_by),
              direction: String(m.direction) as Direction,
              ...(typeof m.priority === 'string' ? { priority: m.priority as 'high' | 'medium' | 'low' } : {}),
            }))
        : undefined
      const a = council.assess({
        target: String(args.target),
        ...(Array.isArray(args.directions) ? { directions: args.directions.map(String) as Direction[] } : {}),
        ...(manual === undefined ? {} : { manual }),
      })
      return {
        target: a.target,
        shape: a.shape,
        understanding: a.understanding,
        covered: [...a.covered],
        blockers: [...a.blockers],
        skipped: a.skipped.map((s) => `${s.direction}: ${s.reason}`),
        hypotheses: a.hypotheses.map((h) => ({
          id: h.id,
          statement: h.statement,
          falsifiable_by: h.falsifiableBy,
          direction: h.direction as string,
          priority: h.priority,
          origin: h.origin,
        })),
      }
    },
  }

  const run: ToolDefinition = {
    name: 'council_run',
    description:
      '太尉（调度）：把假设拆成任务、交御史大夫审批、派给最合适的执行体、汇总结果。' +
      '预算/限流/熔断全部由确定性代码判断并记账，被拦下的任务带原因返回而不是静默跳过。' +
      '每份产物都会生成带 sha256 的证据清单。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        directions: { type: 'array', items: { type: 'string' } },
        max_tasks: { type: 'number', description: '最多执行几条任务，默认 3。' },
        claim_id: { type: 'string', description: 'Optional: attach all evidence to this claim.' },
        manual_hypotheses: { type: 'array', items: { type: 'object' } },
      },
      required: ['target'],
    },
    output: {
      schema: RUN_SCHEMA,
      render: (_a: unknown, v: unknown) => [{ type: 'text', text: renderRun(v as Record<string, unknown>) }],
    },
    async execute(args: Record<string, unknown>) {
      const controller = new AbortController()
      const manual = Array.isArray(args.manual_hypotheses)
        ? (args.manual_hypotheses as Record<string, unknown>[])
            .filter((m) => typeof m.statement === 'string' && typeof m.falsifiable_by === 'string' && typeof m.direction === 'string')
            .map((m) => ({
              statement: String(m.statement),
              falsifiableBy: String(m.falsifiable_by),
              direction: String(m.direction) as Direction,
              ...(typeof m.priority === 'string' ? { priority: m.priority as 'high' | 'medium' | 'low' } : {}),
            }))
        : undefined

      const { plan, summary } = await council.run({
        target: String(args.target),
        ...(Array.isArray(args.directions) ? { directions: args.directions.map(String) as Direction[] } : {}),
        ...(typeof args.max_tasks === 'number' ? { maxTasks: args.max_tasks } : {}),
        ...(typeof args.claim_id === 'string' ? { claimId: args.claim_id } : {}),
        ...(manual === undefined ? {} : { manual }),
        signal: controller.signal,
      })

      return {
        target: summary.target,
        planned: plan.tasks.length,
        executed: summary.results.length,
        settled: summary.settled,
        found: summary.found,
        findings: summary.findings,
        exposures: summary.exposures,
        cleans: summary.cleans,
        inconclusive: summary.inconclusive,
        failed: summary.failed,
        blocked: summary.blocked,
        spent: summary.spent,
        tasks: summary.results.map((r) => ({
          task: r.contract.id,
          direction: r.contract.direction as string,
          hypothesis: r.contract.hypothesisId ?? '',
          outcome: r.outcome,
          ...(r.found === undefined ? {} : { found: r.found }),
          ...(r.findingClass === undefined ? {} : { class: r.findingClass }),
          ...(r.agentId === undefined ? {} : { agent: r.agentId }),
          ...(r.reason === undefined ? {} : { reason: r.reason }),
          ...(r.detail === undefined ? {} : { detail: r.detail }),
          cost: r.cost,
          ...(r.evidenceDir === undefined ? {} : { evidence_dir: r.evidenceDir }),
          ...(r.manifest === undefined ? {} : { manifest_digest: manifestDigestOf(r.manifest.entries.map((e) => `${e.path}:${e.sha256}`)) }),
        })),
        skipped: plan.skipped.map((s) => `${s.hypothesisId}: ${s.reason}`),
        next_actions: [...summary.nextActions],
      }
    },
  }

  const status: ToolDefinition = {
    name: 'council_status',
    description:
      '御史大夫（风控）+ 太尉（状态）+ 人才档案 + 误报账本 + 奖惩信誉：授权范围、限流与熔断状态、任务板、' +
      '每个 agent 的履历与误报率、当前信誉分（决定下一轮先试谁）、以及已接入的执行体类型。' +
      '判断「还能不能继续跑」「该不该信某个工具」「为什么这张牌被排到后面」看这里，不要靠猜。',
    parameters: { type: 'object', properties: {} },
    output: {
      schema: STATUS_SCHEMA,
      render: (_a: unknown, v: unknown) => [{ type: 'text', text: renderStatus(v as Record<string, unknown>) }],
    },
    async execute() {
      const s = council.status()
      return {
        limits: {
          rate_window_s: Math.round(s.policy.rateWindowMs / 1000),
          rate_max_per_window: s.policy.rateMaxPerWindow,
          breaker_threshold: s.policy.breakerThreshold,
          max_task_timeout_ms: s.policy.maxTaskTimeoutMs,
          scope: s.policy.allowedHosts.length === 0 ? 'unrestricted' : s.policy.allowedHosts.join(','),
        },
        runs: s.ledger.runs.map((r) => ({
          direction: r.direction as string,
          runs: r.runs,
          faults: r.faults,
          in_window: r.inWindow,
        })),
        blocked: s.ledger.blocked.map((b) => ({ code: b.code as string, count: b.count })),
        open_breakers: s.ledger.openBreakers.map((b) => `${b.direction} until ${new Date(b.until).toISOString()} (last: ${b.lastFault})`),
        board: s.board.map((b) => ({
          task: b.taskId,
          direction: b.direction as string,
          status: b.status,
          ...(b.outcome === undefined ? {} : { outcome: b.outcome }),
          cost: b.cost,
          ...(b.note === undefined ? {} : { note: b.note }),
        })),
        roster: s.roster.map((r) => ({
          agent: r.id,
          runs: r.runs,
          settled: r.settled,
          inconclusive: r.inconclusive,
          failed: r.failed,
          found: r.foundCount,
          ...(r.lastOutcome === undefined ? {} : { last_outcome: r.lastOutcome }),
          ...(r.lastFault === undefined ? {} : { last_fault: r.lastFault }),
        })),
        adapters: s.adapters.map((a) => ({ kind: a.kind as string, describe: a.describe })),
        precision: s.precision.agents.map((a) => ({
          agent: a.agent,
          reported: a.reported,
          confirmed: a.confirmed,
          refuted: a.refuted,
          open: a.open,
          sample: a.sample,
          ...(a.falsePositiveRate === undefined ? {} : { false_positive_rate: a.falsePositiveRate }),
          ...(a.note === undefined ? {} : { note: a.note }),
        })),
        unattributed_refutations: s.precision.unattributedRefutations,
        precision_actions: s.precisionActions,
        // 奖惩：谁因为这轮之前的战绩被提前或压后。effective_priority 是排序真正用的数，
        // 和作者写的 priority 不同——差异就是奖惩本身。
        credit_by_shape: s.creditByShape.map((c) => ({
          key: c.agent,
          value: Number(c.value.toFixed(3)),
          confirmed: c.confirmed,
          refuted: c.refuted,
          basis: c.basis,
        })),
        credit: s.credit.map((c) => ({
          agent: c.agent,
          value: Number(c.value.toFixed(3)),
          posterior: Number(c.posterior.toFixed(3)),
          explore: Number(c.explore.toFixed(3)),
          confirmed: c.confirmed,
          refuted: c.refuted,
          sample: c.sample,
          runs: c.runs,
          basis: c.basis,
        })),
      }
    },
  }

  return [assess, run, status]
}

function manifestDigestOf(parts: readonly string[]): string {
  // 简化摘要：只用于让人肉眼比对两批证据是否同一批
  let h = 0
  for (const p of parts) {
    for (let i = 0; i < p.length; i += 1) h = (h * 31 + p.charCodeAt(i)) | 0
  }
  return (h >>> 0).toString(16)
}

function renderAssessment(r: Record<string, unknown>): string {
  const lines = [
    `target=${String(r.target)}`,
    `shape=${String(r.shape)}`,
    `understanding=${String(r.understanding)}`,
  ]
  const covered = (r.covered ?? []) as string[]
  if (covered.length > 0) lines.push(`covered=${covered.join(',')}`)
  const blockers = (r.blockers ?? []) as string[]
  for (const b of blockers) lines.push(`blocker: ${b}`)
  for (const s of (r.skipped ?? []) as string[]) lines.push(`skipped: ${s}`)
  const hs = (r.hypotheses ?? []) as Array<Record<string, unknown>>
  lines.push(`hypotheses=${hs.length}`)
  for (const h of hs) {
    lines.push(`  ${String(h.id)} [${String(h.priority)}] ${String(h.direction)} — ${String(h.statement)}`)
    lines.push(`    falsifiable_by=${String(h.falsifiable_by)}`)
  }
  return lines.join('\n')
}

function renderRun(r: Record<string, unknown>): string {
  const lines = [
    `target=${String(r.target)}`,
    `planned=${String(r.planned)} executed=${String(r.executed)} spent=${String(r.spent)}`,
    `settled=${String(r.settled)} found=${String(r.found)} inconclusive=${String(r.inconclusive)} failed=${String(r.failed)} blocked=${String(r.blocked)}`,
    `by class: finding=${String(r.findings ?? 0)} exposure=${String(r.exposures ?? 0)} clean=${String(r.cleans ?? 0)}`,
  ]
  const tasks = (r.tasks ?? []) as Array<Record<string, unknown>>
  if (tasks.length > 0) {
    lines.push('tasks:')
    for (const t of tasks) {
      const extra = [
        t.class === undefined ? undefined : `class=${String(t.class)}`,
        t.agent === undefined ? undefined : `agent=${String(t.agent)}`,
        t.detail === undefined ? undefined : `detail=${String(t.detail)}`,
        t.reason === undefined ? undefined : `reason=${String(t.reason)}`,
        typeof t.evidence_dir === 'string' ? `evidence=${t.evidence_dir}` : undefined,
      ].filter((x) => x !== undefined)
      lines.push(`  ${String(t.direction)} outcome=${String(t.outcome)}${extra.length === 0 ? '' : ' ' + extra.join(' ')}`)
    }
  }
  const skipped = (r.skipped ?? []) as string[]
  for (const s of skipped) lines.push(`skipped: ${s}`)
  const next = (r.next_actions ?? []) as string[]
  if (next.length > 0) {
    lines.push('next:')
    for (const n of next) lines.push(`  - ${n}`)
  }
  return lines.join('\n')
}

function renderStatus(r: Record<string, unknown>): string {
  const lim = r.limits as Record<string, unknown>
  const lines = [
    `limits: scope=${String(lim.scope)} rate=${String(lim.rate_max_per_window)}/${String(lim.rate_window_s)}s breaker=${String(lim.breaker_threshold)} max_timeout=${String(lim.max_task_timeout_ms)}ms`,
  ]
  const runs = (r.runs ?? []) as Array<Record<string, unknown>>
  if (runs.length > 0) {
    lines.push(`runs: ${runs.map((x) => `${String(x.direction)}=${String(x.runs)}(faults=${String(x.faults)},window=${String(x.in_window)})`).join(' ')}`)
  }
  const blocked = (r.blocked ?? []) as Array<Record<string, unknown>>
  if (blocked.length > 0) {
    lines.push(`blocked: ${blocked.map((b) => `${String(b.code)}=${String(b.count)}`).join(' ')}`)
  }
  const breakers = (r.open_breakers ?? []) as string[]
  lines.push(`open_breakers=${breakers.length === 0 ? 'none' : breakers.join('; ')}`)
  const board = (r.board ?? []) as Array<Record<string, unknown>>
  lines.push(`board=${board.length}`)
  for (const e of board.slice(-10)) {
    lines.push(`  ${String(e.direction)} ${String(e.status)}${e.outcome === undefined ? '' : ` outcome=${String(e.outcome)}`}${e.note === undefined ? '' : ` — ${String(e.note)}`}`)
  }
  const credit = (r.credit ?? []) as Array<Record<string, unknown>>
  if (credit.length > 0) {
    lines.push(`credit=${credit.length}（奖惩：value 越高越靠前；顺序即下一轮派活顺序）`)
    for (const c of credit) {
      const v = Number(c.value)
      const mark = v > 0.6 ? '↑' : v < 0.4 ? '↓' : '='
      lines.push(
        `  ${mark} ${String(c.agent)} value=${String(c.value)} (posterior=${String(c.posterior)} explore=${String(c.explore)}) ` +
          `confirmed=${String(c.confirmed)} refuted=${String(c.refuted)} runs=${String(c.runs)}`,
      )
    }
  }
  const byShape = (r.credit_by_shape ?? []) as Array<Record<string, unknown>>
  if (byShape.length > 0) {
    lines.push(`credit 按形态分层（样本够的才列；全局分会被形态差异平均掉）:`)
    for (const c of byShape) {
      lines.push(`  ${String(c.key)} value=${String(c.value)} ${String(c.confirmed)}C/${String(c.refuted)}R`)
    }
  }
  const roster = (r.roster ?? []) as Array<Record<string, unknown>>
  lines.push(`roster=${roster.length}`)
  for (const a of roster) {
    lines.push(
      `  ${String(a.agent)} runs=${String(a.runs)} settled=${String(a.settled)} inconclusive=${String(a.inconclusive)} failed=${String(a.failed)} found=${String(a.found)}` +
        (a.last_fault === undefined ? '' : ` last_fault=${String(a.last_fault)}`),
    )
  }
  const adapters = (r.adapters ?? []) as Array<Record<string, unknown>>
  for (const ad of adapters) lines.push(`adapter ${String(ad.kind)}: ${String(ad.describe)}`)

  const precision = (r.precision ?? []) as Array<Record<string, unknown>>
  lines.push(`precision: ${precision.length === 0 ? 'no claims yet' : ''}`)
  for (const p of precision) {
    const rate =
      typeof p.false_positive_rate === 'number'
        ? `fpr=${Math.round(p.false_positive_rate * 100)}%`
        : 'fpr=n/a'
    lines.push(
      `  ${String(p.agent)} reported=${String(p.reported)} confirmed=${String(p.confirmed)} refuted=${String(p.refuted)} open=${String(p.open)} ${rate}` +
        (typeof p.note === 'string' ? ` (${p.note})` : ''),
    )
  }
  if (typeof r.unattributed_refutations === 'number' && r.unattributed_refutations > 0) {
    lines.push(`unattributed_refutations=${String(r.unattributed_refutations)}`)
  }
  const pActions = (r.precision_actions ?? []) as string[]
  for (const a of pActions) lines.push(`precision_note: ${a}`)
  return lines.join('\n')
}

export function installCouncilTools(ctx: Context, council: Council): void {
  for (const tool of councilTools(council)) ctx.tools.register(tool)
}
