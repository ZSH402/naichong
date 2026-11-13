/**
 * 御史大夫：授权范围、限流、超时、熔断。
 *
 * 不管预算。预算是「我打算花多少」的策略问题，属于调度层（那是每次派活
 * 自己的耐心和额度）；御史大夫管的是「能不能碰这个目标」的授权问题。
 * 把两件事塞进一个角色，会让「预算不够」和「越界」看起来是同一种拒绝，
 * 而它们的处置完全不同：前者可以加预算，后者一步都不能退。
 *
 * 全部是确定性代码。让模型来判断「还剩几次」「熔断开没开」是最典型的
 * 用不确定的东西做确定的事。
 */

import type { Direction } from '../agent-registry.ts'
import type { TaskContract } from './contract.ts'

export interface CensorPolicy {
  /** 限流窗口（毫秒）。 */
  readonly rateWindowMs: number
  /** 一个窗口内同方向最多几次。 */
  readonly rateMaxPerWindow: number
  /** 同方向连续失败几次开闸。 */
  readonly breakerThreshold: number
  /** 开闸后的冷却（毫秒）。 */
  readonly breakerCooldownMs: number
  /** 单条任务的超时兜底上限。 */
  readonly maxTaskTimeoutMs: number
  /** 授权目标（精确匹配主机名），空数组表示不做范围约束。 */
  readonly allowedHosts: readonly string[]
}

export const CENSOR_DEFAULTS: CensorPolicy = {
  rateWindowMs: 60_000,
  rateMaxPerWindow: 6,
  breakerThreshold: 3,
  breakerCooldownMs: 120_000,
  maxTaskTimeoutMs: 1_800_000,
  allowedHosts: [],
}

export type DenyCode = 'scope' | 'rate-limit' | 'breaker-open' | 'timeout-too-large'

export interface Authorization {
  readonly allowed: boolean
  readonly code?: DenyCode
  readonly reason?: string
}

export interface LedgerView {
  /** 各方向累计执行次数。 */
  readonly runs: readonly { direction: Direction; runs: number; faults: number; inWindow: number }[]
  readonly openBreakers: readonly { direction: Direction; until: number; lastFault: string }[]
  readonly blocked: readonly { code: DenyCode; count: number }[]
}

interface BreakerState {
  consecutiveFaults: number
  openUntil: number
  lastFault: string
}

/** 从 URL / 主机 / 命令里抠出主机名，用于范围判定。 */
export function hostOf(target: string): string | undefined {
  const t = target.trim()
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return new URL(t).hostname.toLowerCase()
  } catch {
    return undefined
  }
  // host:port
  const m = /^([a-z0-9._-]+)(?::\d{1,5})?$/i.exec(t)
  if (m?.[1] !== undefined) return m[1].toLowerCase()
  // 命令行里取第一个看起来像主机名的 token
  for (const token of t.split(/\s+/)) {
    const mm = /^([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i.exec(token)
    if (mm?.[1] !== undefined) return mm[1].toLowerCase()
  }
  return undefined
}

export class Censor {
  private readonly policy: CensorPolicy
  private readonly breakers = new Map<Direction, BreakerState>()
  private readonly windows = new Map<Direction, number[]>()
  private readonly runCount = new Map<Direction, number>()
  private readonly faultCount = new Map<Direction, number>()
  private readonly blockedCount = new Map<DenyCode, number>()
  private readonly now: () => number

  constructor(policy: Partial<CensorPolicy> = {}, options: { now?: () => number } = {}) {
    this.policy = { ...CENSOR_DEFAULTS, ...policy }
    this.now = options.now ?? Date.now
  }

  /**
   * 执行前审批。四条独立否决线，任一触发即拒绝。
   *
   * 不做预扣，因为没有额度可扣——限流的计数在执行时写，不在这里写。
   * 这样即使调用方批了不跑（release），也不会留下一条幽灵记录。
   */
  authorize(contract: TaskContract): Authorization {
    const deny = (code: DenyCode, reason: string): Authorization => {
      this.blockedCount.set(code, (this.blockedCount.get(code) ?? 0) + 1)
      return { allowed: false, code, reason }
    }

    if (this.policy.allowedHosts.length > 0) {
      const host = hostOf(contract.target)
      if (host === undefined) {
        return deny('scope', `cannot determine host from target "${clip(contract.target)}"`)
      }
      if (!this.policy.allowedHosts.some((h) => h.toLowerCase() === host)) {
        return deny('scope', `host "${host}" is not in the authorized list`)
      }
    }

    const breaker = this.breakers.get(contract.direction)
    if (breaker !== undefined && breaker.openUntil > this.now()) {
      return deny(
        'breaker-open',
        `${contract.direction} breaker open for another ${Math.ceil((breaker.openUntil - this.now()) / 1000)}s (last fault: ${breaker.lastFault})`,
      )
    }

    const window = this.windowOf(contract.direction)
    if (window.length >= this.policy.rateMaxPerWindow) {
      return deny(
        'rate-limit',
        `${contract.direction} already ran ${window.length} time(s) in the last ${Math.round(this.policy.rateWindowMs / 1000)}s`,
      )
    }

    if ((contract.timeoutMs ?? 0) > this.policy.maxTaskTimeoutMs) {
      return deny('timeout-too-large', `requested timeout ${String(contract.timeoutMs)}ms exceeds the cap ${String(this.policy.maxTaskTimeoutMs)}ms`)
    }

    return { allowed: true }
  }

  /**
   * 记录一次执行的实际结果。审批通过后必须调用，限流窗口与熔断都靠它更新。
   *
   * outcome 只影响熔断：ok 清零、fault 累计、neutral（未定论/被拒）两者都不做。
   * neutral 不构成「这个方向在坏」的证据，把它算进熔断会因为「目标太硬」
   * 而把整个方向锁死。
   */
  settle(contract: TaskContract, outcome: 'ok' | 'fault' | 'neutral'): void {
    const window = this.windowOf(contract.direction)
    window.push(this.now())

    this.runCount.set(contract.direction, (this.runCount.get(contract.direction) ?? 0) + 1)

    const breaker = this.breakers.get(contract.direction) ?? { consecutiveFaults: 0, openUntil: 0, lastFault: '' }
    if (outcome === 'fault') {
      breaker.consecutiveFaults += 1
      breaker.lastFault = contract.id
      this.faultCount.set(contract.direction, (this.faultCount.get(contract.direction) ?? 0) + 1)
      if (breaker.consecutiveFaults >= this.policy.breakerThreshold) {
        breaker.openUntil = this.now() + this.policy.breakerCooldownMs
      }
    } else if (outcome === 'ok') {
      breaker.consecutiveFaults = 0
      breaker.openUntil = 0
    }
    this.breakers.set(contract.direction, breaker)
  }

  /** 兼容旧调用点：审批通过但没执行，什么也不用回退。 */
  release(_contract: TaskContract): void {
    /* 无预扣，无需释放 */
  }

  private windowOf(direction: Direction): number[] {
    const kept = (this.windows.get(direction) ?? []).filter((t) => this.now() - t < this.policy.rateWindowMs)
    this.windows.set(direction, kept)
    return kept
  }

  ledger(): LedgerView {
    const directions = new Set<Direction>([...this.runCount.keys(), ...this.breakers.keys()])
    return {
      runs: [...directions].map((d) => ({
        direction: d,
        runs: this.runCount.get(d) ?? 0,
        faults: this.faultCount.get(d) ?? 0,
        inWindow: this.windowOf(d).length,
      })),
      openBreakers: [...this.breakers.entries()]
        .filter(([, b]) => b.openUntil > this.now())
        .map(([d, b]) => ({ direction: d, until: b.openUntil, lastFault: b.lastFault })),
      blocked: [...this.blockedCount.entries()].map(([code, count]) => ({ code, count })),
    }
  }

  viewPolicy(): CensorPolicy {
    return this.policy
  }
}

function clip(s: string): string {
  return s.length <= 60 ? s : `${s.slice(0, 57)}...`
}
