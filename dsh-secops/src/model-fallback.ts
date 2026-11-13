/**
 * Model Fallback：provider 失败时自动切到备用路由。
 *
 * 为什么需要：DSH 只有 retry（同一 provider 重试），没有 failover。
 * 当一个 provider 限流、宕机或鉴权失效时，retry 只会把同样的失败重放 N 次。
 *
 * 落点是两个现成接缝：
 *   - `agent/request-error` waterfall：拿到失败详情，决定是否切换并返回 retry
 *   - `agent/request` waterfall：返回替换后的 LlmCallConfig，把下一次请求指到备用路由
 *
 * 关键设计：**只对可恢复的失败切换**。上下文超限、用户取消、内容拒绝这些
 * 换 provider 也解决不了，切了反而把真实问题掩盖成"所有 provider 都失败"。
 */

import type { LlmFailure } from '@deepseek-ai/dsh-llm'

/** 只需要改这两个字段，其余 controls 由调用方保留。 */
export interface RouteChoice {
  readonly provider: string
  readonly model: string
}

export interface FallbackRoute {
  readonly provider: string
  readonly model: string
}

export interface ModelFallbackOptions {
  /** 按优先级排列的路由，第一个是主路由。 */
  readonly routes: readonly FallbackRoute[]
  /** 单个 agent 最多切换几次，防止在坏 provider 之间来回跳。默认 3。 */
  readonly maxSwitches?: number
  /** 可选：自定义判定，覆盖默认的 shouldFailover。 */
  readonly shouldFailover?: (failure: LlmFailure) => boolean
}

/** 一次切换的记录，用于诊断。 */
export interface FailoverRecord {
  readonly agentId: string
  readonly from: string
  readonly to: string
  readonly code: string
  readonly status?: number
  readonly at: number
}

const DEFAULT_MAX_SWITCHES = 3

/**
 * 默认判定：哪些失败值得换 provider。
 *
 * 不切的情况很关键：
 *   - 上下文超限（换 provider 也装不下）
 *   - 用户取消（不是 provider 的问题）
 *   - 内容策略拒绝（换 provider 是规避审核，不是修复）
 */
export function shouldFailover(failure: LlmFailure): boolean {
  const code = failure.code.toUpperCase()

  // 明确不该切的
  if (code.includes('CONTEXT_WINDOW') || code.includes('QUOTA')) return false
  if (code.includes('ABORT') || code.includes('CANCEL')) return false
  if (code.includes('REFUSAL') || code.includes('CONTENT')) return false
  if (code.includes('INVALID_CREDENTIAL')) {
    // 鉴权失败值得切：换 provider 可能用另一套凭据
    return true
  }

  // HTTP 语义
  const status = failure.status
  if (status !== undefined) {
    if (status === 429) return true
    if (status >= 500 && status <= 599) return true
    if (status === 401 || status === 403) return true
    if (status === 408) return true
    return false
  }

  // 传输层
  // 注意 ETIMEDOUT 里是 TIMEDOUT 不是 TIMEOUT，两个都要覆盖
  if (/TIMEOUT|TIMEDOUT|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|SOCKET|EPIPE/.test(code)) return true
  if (/RATE[_ ]?LIMIT|OVERLOAD|UNAVAILABLE/.test(code)) return true

  return false
}

/** 每个 agent 的 fallback 状态。 */
interface AgentState {
  /** 当前使用的路由下标。 */
  cursor: number
  /** 已切换次数。 */
  switches: number
}

export class ModelFallback {
  private readonly routes: readonly FallbackRoute[]
  private readonly maxSwitches: number
  private readonly decide: (failure: LlmFailure) => boolean
  private readonly states = new Map<string, AgentState>()
  private readonly records: FailoverRecord[] = []

  constructor(options: ModelFallbackOptions) {
    if (options.routes.length === 0) throw new Error('model-fallback: routes must not be empty')
    this.routes = options.routes
    this.maxSwitches = Math.max(0, options.maxSwitches ?? DEFAULT_MAX_SWITCHES)
    this.decide = options.shouldFailover ?? shouldFailover
  }

  get enabled(): boolean {
    return this.routes.length > 1
  }

  private stateOf(agentId: string): AgentState {
    let s = this.states.get(agentId)
    if (s === undefined) {
      s = { cursor: 0, switches: 0 }
      this.states.set(agentId, s)
    }
    return s
  }

  /**
   * 处理一次请求失败。返回 true 表示已经切换到备用路由，调用方应 retry。
   *
   * 幂等：同一 agent 连续失败会逐级下移，用尽后就返回 false（交回原有错误处理）。
   */
  onRequestError(agentId: string, failure: LlmFailure): boolean {
    if (!this.enabled) return false
    const state = this.stateOf(agentId)
    if (state.switches >= this.maxSwitches) return false
    if (!this.decide(failure)) return false
    if (state.cursor >= this.routes.length - 1) return false

    const from = this.routes[state.cursor]!
    state.cursor += 1
    state.switches += 1
    const to = this.routes[state.cursor]!

    this.records.push({
      agentId,
      from: `${from.provider}/${from.model}`,
      to: `${to.provider}/${to.model}`,
      code: failure.code,
      ...(failure.status === undefined ? {} : { status: failure.status }),
      at: Date.now(),
    })
    return true
  }

  /**
   * 在 `agent/request` 里调用：给出应当使用的路由。
   *
   * 返回 undefined 表示不要改（沿用原配置）。
   */
  routeFor(agentId: string, current: { provider: string; model: string }): RouteChoice | undefined {
    if (!this.enabled) return undefined
    const state = this.stateOf(agentId)
    // 用 cursor 判断是否已偏离主路由，而不是 switches ——
    // onSuccess 会把 switches 归零（重新获得切换额度），但不应该把路由退回去。
    if (state.cursor === 0) return undefined
    const target = this.routes[state.cursor]
    if (target === undefined) return undefined
    if (target.provider === current.provider && target.model === current.model) return undefined
    return { provider: target.provider, model: target.model }
  }

  /** 成功一次后重置计数（但不回退路由：回到坏 provider 会再失败一轮）。 */
  onSuccess(agentId: string): void {
    const state = this.states.get(agentId)
    if (state !== undefined) state.switches = 0
  }

  /** 切换记录，供诊断与审计。 */
  history(): readonly FailoverRecord[] {
    return this.records
  }

  /** 当前各 agent 的路由状态。 */
  snapshot(): { agentId: string; route: string; switches: number }[] {
    return [...this.states.entries()].map(([agentId, s]) => ({
      agentId,
      route: `${this.routes[s.cursor]?.provider}/${this.routes[s.cursor]?.model}`,
      switches: s.switches,
    }))
  }
}
