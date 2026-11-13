/**
 * 太尉：拆解任务、选执行体、维护状态、汇总结果。
 *
 * 它不做判断——判断在丞相（测什么）和御史（能不能测）。太尉只负责
 * 把已批准的假设变成一串可执行的任务，盯着它们跑完，再把结果整理成
 * 一份能直接喂回丞相的东西。
 *
 * 一条任务被御史驳回不该拖垮整个计划：其他方向照跑，被驳回的那条
 * 带着原因进汇总。计划是一次性的，可观测性不是。
 */

import fs from 'node:fs'
import type { AgentRegistry, Direction } from '../agent-registry.ts'
import type { Assessment, Hypothesis } from './chancellor.ts'
import type { AdapterRegistry, TaskContract, TaskKind, TaskResult } from './contract.ts'
import { nextTaskId } from './contract.ts'
import type { Censor } from './censor.ts'
import { estimateCost } from './adapters.ts'
import type { CoverageLedger, StampStatus } from '../coverage.ts'
import { extractAssets } from '../asset-store.ts'

/** 任务结局 → 覆盖戳状态。没测成和测过没发现必须分开。 */
function stampStatusOf(outcome: TaskResult['outcome'], reason: string | undefined): StampStatus {
  if (outcome === 'settled') return 'complete'
  if (outcome === 'inconclusive') return 'partial'
  if (outcome === 'blocked') {
    // no-fit 的意思是「没有工具能吃这个目标」，等于没测
    return reason !== undefined && reason.startsWith('no-fit') ? 'no-input' : 'failed'
  }
  return 'failed'
}

export interface PlannedTask {
  readonly contract: TaskContract
  readonly hypothesis: Hypothesis
  readonly adapter: TaskKind
}

export interface MarshalPlan {
  readonly target: string
  readonly tasks: readonly PlannedTask[]
  /** 被计划阶段就排除的假设，带原因。 */
  readonly skipped: readonly { readonly hypothesisId: string; readonly reason: string }[]
}

export type BoardStatus = 'planned' | 'running' | 'done' | 'blocked' | 'failed'

export interface BoardEntry {
  readonly taskId: string
  readonly direction: Direction
  readonly target: string
  readonly hypothesisId: string
  readonly status: BoardStatus
  readonly outcome?: TaskResult['outcome']
  readonly found?: boolean
  readonly cost: number
  readonly updatedAt: number
  readonly note?: string
}

export interface MarshalSummary {
  readonly target: string
  readonly settled: number
  readonly found: number
  /** 其中可直接利用的。 */
  readonly findings: number
  /** 其中只是暴露面/配置问题的。 */
  readonly exposures: number
  /** 明确查过没问题的。 */
  readonly cleans: number
  readonly inconclusive: number
  readonly failed: number
  readonly blocked: number
  readonly spent: number
  readonly results: readonly TaskResult[]
  /** 明确的下一条动作建议，喂回丞相 / 直接给主控。 */
  readonly nextActions: readonly string[]
}

export interface MarshalOptions {
  readonly registry: AgentRegistry
  readonly adapters: AdapterRegistry
  readonly censor: Censor
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
  /** 任务板落盘路径；不传则只在内存。 */
  readonly boardPath?: string
  /** 覆盖账本。给了就自动记账——「什么还没测」不该靠人记。 */
  readonly coverage?: CoverageLedger
  /** 资产库。给了就把每次扫描结果解析成可查询的资产。 */
  readonly assets?: import('../asset-store.ts').AssetStore
}

export class Marshal {
  private readonly registry: AgentRegistry
  private readonly adapters: AdapterRegistry
  private readonly censor: Censor
  private readonly logger: MarshalOptions['logger']
  private readonly boardPath: string | undefined
  private readonly coverage: CoverageLedger | undefined
  private readonly assets: MarshalOptions['assets']
  private readonly board = new Map<string, BoardEntry>()

  constructor(options: MarshalOptions) {
    this.registry = options.registry
    this.adapters = options.adapters
    this.censor = options.censor
    this.logger = options.logger
    this.boardPath = options.boardPath
    this.coverage = options.coverage
    this.assets = options.assets
    if (this.boardPath !== undefined) this.loadBoard()
  }

  /**
   * 从任务板恢复。
   *
   * 只写不读的板等于没有板：重启后看板上什么都没有，而「跨会话看进度」
   * 恰恰是它存在的唯一理由。半行（写入中途崩溃）直接跳过。
   */
  private loadBoard(): void {
    if (this.boardPath === undefined) return
    let raw: string
    try {
      raw = fs.readFileSync(this.boardPath, 'utf8')
    } catch {
      return
    }
    for (const line of raw.split('\n')) {
      const t = line.trim()
      if (t === '') continue
      try {
        const entry = JSON.parse(t) as BoardEntry
        if (typeof entry.taskId === 'string') this.board.set(entry.taskId, entry)
      } catch {
        /* 半行忽略 */
      }
    }
  }

  /**
   * 把丞相的假设拆成任务。
   *
   * 拆解规则是确定的：一条假设 → 一条任务，方向照搬，预估代价取该方向
   * 最便宜的可用候选。不为一条假设生成多条任务——那会让预算失控，
   * 也会让「这条证据支持哪条假设」的对应关系变得模糊。
   */
  plan(assessment: Assessment, options: { readonly claimId?: string; readonly requestedBy?: TaskContract['requestedBy'] } = {}): MarshalPlan {
    const tasks: PlannedTask[] = []
    const skipped: { hypothesisId: string; reason: string }[] = []
    const kinds = this.adapters.kinds()

    // 同方向轮转分配，别让两条任务都落在同一个 agent 上。
    // 全落给同一个 agent 等于花两次钱买同一个结论，而多候选一次也没被试过。
    const rotation = new Map<Direction, number>()

    for (const h of assessment.hypotheses) {
      const available = this.registry.accepting(h.direction, assessment.shape as never)
      if (available.length === 0) {
        skipped.push({ hypothesisId: h.id, reason: `no agent in ${h.direction} accepts shape "${assessment.shape}"` })
        continue
      }
      const turn = rotation.get(h.direction) ?? 0
      const preferred = available[turn % available.length]!
      rotation.set(h.direction, turn + 1)
      // 按候选**自己声明的** kind 派活。
      // 之前写死 code-tool，结果 mcp / agent 类的候选永远轮不到——
      // 注册了等于没注册。候选说自己是 mcp，就交给 mcp adapter。
      const kindOf = (c: { readonly kind: 'cli' | 'mcp' | 'subagent' }): TaskKind =>
        c.kind === 'mcp' ? 'mcp' : c.kind === 'subagent' ? 'agent' : 'code-tool'
      const want = kindOf(preferred)
      const kind: TaskKind = kinds.includes(want) ? want : kinds.includes('code-tool') ? 'code-tool' : (kinds[0] ?? 'code-tool')
      const cost = estimateCost(this.registry, h.direction, h.target)
      const contract: TaskContract = {
        id: nextTaskId(h.direction, kind),
        kind,
        direction: h.direction,
        target: h.target,
        estimatedCost: cost,
        // 超时在这里定死，不留 undefined。
        // 御史大夫按契约里的值判断是否超上限，undefined 会直接跳过检查——
        // 那等于"没写就无限"，而上限存在的唯一意义就是挡住这种没写。
        timeoutMs: preferred.defaultTimeoutMs ?? 120_000,
        requestedBy: options.requestedBy ?? 'marshal',
        rationale: h.statement,
        hypothesisId: h.id,
        preferredAgentId: preferred.id,
        agentId: preferred.id,
        ...(options.claimId === undefined ? {} : { claimId: options.claimId }),
      }
      tasks.push({ contract, hypothesis: h, adapter: kind })
    }

    return { target: assessment.target, tasks, skipped }
  }

  /** 逐个执行。御史驳一条不影响其他条。 */
  async execute(plan: MarshalPlan, signal: AbortSignal): Promise<MarshalSummary> {
    const results: TaskResult[] = []
    let spent = 0

    for (const task of plan.tasks) {
      if (signal.aborted) {
        this.logger?.warn('marshal: aborted, remaining tasks not started')
        break
      }

      this.upsert({
        taskId: task.contract.id,
        direction: task.contract.direction,
        target: task.contract.target,
        hypothesisId: task.hypothesis.id,
        status: 'running',
        cost: 0,
        updatedAt: Date.now(),
      })

      const auth = this.censor.authorize(task.contract)
      if (!auth.allowed) {
        const blocked: TaskResult = {
          contract: task.contract,
          outcome: 'blocked',
          reason: `${auth.code}: ${auth.reason}`,
          durationMs: 0,
          cost: 0,
        }
        results.push(blocked)
        this.upsert({
          taskId: task.contract.id,
          direction: task.contract.direction,
          target: task.contract.target,
          hypothesisId: task.hypothesis.id,
          status: 'blocked',
          outcome: 'blocked',
          cost: 0,
          updatedAt: Date.now(),
          ...(auth.reason === undefined ? {} : { note: auth.reason }),
        })
        this.logger?.warn(`marshal: blocked ${task.contract.id} — ${auth.code}: ${auth.reason}`)
        continue
      }

      const adapter = this.adapters.resolve(task.adapter)
      if (adapter === undefined) {
        const missing: TaskResult = {
          contract: task.contract,
          outcome: 'refused',
          reason: `no adapter registered for kind "${task.adapter}"`,
          durationMs: 0,
          cost: 0,
        }
        results.push(missing)
        this.upsert({
          taskId: task.contract.id,
          direction: task.contract.direction,
          target: task.contract.target,
          hypothesisId: task.hypothesis.id,
          status: 'failed',
          outcome: 'refused',
          cost: 0,
          updatedAt: Date.now(),
          note: missing.reason,
        })
        continue
      }

      let result: TaskResult
      try {
        result = await adapter.execute(task.contract, {
          signal,
          ...(this.logger === undefined ? {} : { logger: this.logger }),
        })
      } catch (error) {
        // 适配器自己炸了也要记一次，否则熔断看不到这次故障
        this.censor.settle(task.contract, 'fault')
        result = {
          contract: task.contract,
          outcome: 'failed',
          reason: `adapter threw: ${String(error)}`,
          durationMs: 0,
          cost: 0,
        }
      }

      spent += result.cost
      results.push(result)
      // 先把扫描结果解析成资产，再按资产盖检查戳——顺序反了会盖到一个不存在的资产上。
      if (result.found !== undefined) {
        const extracted = extractAssets(
          result.contract.direction,
          result.detail ?? '',
          result.contract.target,
        )
        for (const a of extracted) {
          this.assets?.record({ ...a })
          if (result.findingClass !== undefined) {
            this.assets?.markChecked(a.id, result.contract.direction, result.findingClass)
          }
        }
      }
      this.coverage?.stamp({
        asset: result.contract.target,
        check: result.contract.direction,
        status: stampStatusOf(result.outcome, result.reason),
        ...(result.detail === undefined ? {} : { inputs: result.detail }),
        ...(result.found === undefined ? {} : { outputs: result.found ? 1 : 0 }),
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      })
      this.upsert({
        taskId: result.contract.id,
        direction: result.contract.direction,
        target: result.contract.target,
        hypothesisId: task.hypothesis.id,
        status: result.outcome === 'settled' ? 'done' : result.outcome === 'blocked' ? 'blocked' : 'failed',
        outcome: result.outcome,
        ...(result.found === undefined ? {} : { found: result.found }),
        cost: result.cost,
        updatedAt: Date.now(),
        ...(result.reason === undefined ? {} : { note: result.reason }),
      })
    }

    const summary = this.summarize(plan.target, results, spent)
    this.persist()
    return summary
  }

  private summarize(target: string, results: readonly TaskResult[], spent: number): MarshalSummary {
    const count = (o: TaskResult['outcome']): number => results.filter((r) => r.outcome === o).length
    const foundResults = results.filter((r) => r.found === true)
    const findings = results.filter((r) => r.findingClass === 'finding').length
    const exposures = results.filter((r) => r.findingClass === 'exposure').length
    const cleans = results.filter((r) => r.findingClass === 'clean').length

    const nextActions: string[] = []
    const realFindings = results.filter((r) => r.findingClass === 'finding')
    if (realFindings.length > 0) {
      nextActions.push(
        `有 ${realFindings.length} 条可直接利用的发现（${realFindings.map((r) => r.contract.direction).join(', ')}）；` +
          `经 claim_evidence 登记并走 claim_verify 复现校验——未经验证的发现只是一条线索`,
      )
    }
    const exposureResults = results.filter((r) => r.findingClass === 'exposure')
    if (exposureResults.length > 0) {
      nextActions.push(
        `${exposureResults.length} 条只是暴露面或配置问题（${exposureResults.map((r) => r.contract.direction).join(', ')}）；` +
          `它们本身不构成漏洞，价值在于指向下一步该往哪打——不要当成 finding 上报`,
      )
    }
    const inconclusive = results.filter((r) => r.outcome === 'inconclusive')
    if (inconclusive.length > 0) {
      nextActions.push(
        `${inconclusive.map((r) => r.contract.direction).join(', ')} 跑通了但没有结构化结论；换方法比换工具更有用，或显式要求第二意见`,
      )
    }
    const noFit = results.filter((r) => r.outcome === 'blocked' && (r.reason ?? '').startsWith('no-fit'))
    if (noFit.length > 0) {
      nextActions.push(
        `${noFit.map((r) => r.contract.direction).join(', ')} 没有能吃该目标的工具；需要装对应工具或换目标形态`,
      )
    }
    const budgetBlocked = results.filter((r) => r.outcome === 'blocked' && /budget|breaker|rate/.test(r.reason ?? ''))
    if (budgetBlocked.length > 0) {
      nextActions.push(`御史大夫拦下 ${budgetBlocked.length} 条（预算/限流/熔断）；继续推进需要人工加预算或等冷却`)
    }
    if (results.length > 0 && foundResults.length === 0 && inconclusive.length === 0 && noFit.length === 0) {
      nextActions.push('本轮全部拿到终态且无发现；建议扩大目标面或换方向，重复同一次检查不会带来新信息')
    }

    return {
      target,
      settled: count('settled'),
      found: foundResults.length,
      findings,
      exposures,
      cleans,
      inconclusive: inconclusive.length,
      failed: count('failed') + count('refused'),
      blocked: count('blocked'),
      spent,
      results,
      nextActions,
    }
  }

  private upsert(entry: BoardEntry): void {
    this.board.set(entry.taskId, entry)
  }

  boardEntries(): BoardEntry[] {
    return [...this.board.values()].sort((a, b) => a.updatedAt - b.updatedAt)
  }

  private persist(): void {
    if (this.boardPath === undefined) return
    try {
      const lines = this.boardEntries().map((e) => JSON.stringify(e))
      fs.writeFileSync(this.boardPath, lines.join('\n') + (lines.length === 0 ? '' : '\n'), 'utf8')
    } catch (error) {
      this.logger?.warn(`marshal: failed to persist board — ${String(error)}`)
    }
  }
}
