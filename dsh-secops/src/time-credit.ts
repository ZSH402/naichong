/**
 * 时间信用：基础时间 + 按认知进展续期。
 *
 * 解决的问题是「无进展地烧时间」。前几轮真实观测：连续 45 分钟、150+ 次调用，
 * 换参数、加日志、再跑一遍，产出为零。给再多时间也是同一个循环。
 *
 * 反过来，真正推进认知的动作是稀缺且可识别的：提出一个可证伪的假设、
 * 拿到一条通过相关性校验的强证据、证伪掉一条错误方向。这些出现时给它时间，
 * 没出现就不给。时间因此从「配额」变成「投资回报」。
 *
 * 关键约束：**进展必须由系统判定，不能由模型自述。**
 * 模型说「我有线索了」不算数——`claim_evidence` 的锚点校验通过才算，
 * `claim_refute` 落库才算。这也是这套东西能接在现有证据链上的原因：
 * 强证据的标准已经定义好了，不需要重新发明。
 */

export interface TimeCreditPolicy {
  /** 基础额度。 */
  readonly baseMs: number
  /** 每次有效进展续期多少。 */
  readonly grantMs: number
  /** 总额度上限，防止无限续命把会话拖死。 */
  readonly maxMs: number
  /** 两次续期之间的最小间隔：拦掉「连着交五条证据」这种刷时间。 */
  readonly grantCooldownMs: number
  /** 剩余低于这个值时提醒「该收尾了」。 */
  readonly warnAtMs: number
  /** 每次扣减扣多少。 */
  readonly debitMs: number
  /** 扣减总额上限。 */
  readonly maxDebitMs: number
  /** 两次扣减之间的最小间隔，防止连续停滞一口气扣穿。 */
  readonly debitCooldownMs: number
}

export const DEFAULT_TIME_CREDIT: TimeCreditPolicy = {
  baseMs: 30 * 60 * 1000,
  grantMs: 10 * 60 * 1000,
  maxMs: 120 * 60 * 1000,
  grantCooldownMs: 2 * 60 * 1000,
  warnAtMs: 5 * 60 * 1000,
  // 扣减是「督促换方向」，不是判死刑：单次 5 分钟、总共最多扣掉基础额的一半。
  // 扣穿会让一个只是暂时卡住的合法探索提前结束，而那正是最该被保护的情形。
  debitMs: 5 * 60 * 1000,
  maxDebitMs: 15 * 60 * 1000,
  debitCooldownMs: 5 * 60 * 1000,
}

/** 什么情况下扣时间。名字就是扣减的理由分类。 */
export type DebitKind =
  /** 连续多次相似调用，判定为原地打转。 */
  | 'stall'
  /** 连续在写「搜索答案」类脚本，而不是换假设。 */
  | 'repeat-approach'

/** 哪些动作算进展。名字就是对续期的理由分类。 */
export type ProgressKind =
  /** 提出可证伪的新假设。 */
  | 'hypothesis'
  /** 拿到一条通过锚点校验的强证据。 */
  | 'strong-evidence'
  /** 独立路径增加（换方法复核，不是同一件事做两遍）。 */
  | 'independent-path'
  /** 成功证伪一条方向——排除错误路径和发现漏洞同等有价值。 */
  | 'refutation'
  /** 把一份数据的形状量清楚了（格式、规模、重复度、模板）。
   *  这一步常常直接决定后面几小时走不走偏，值得计价。 */
  | 'structure'

export interface GrantRecord {
  /** 续期按进展分类，扣减按停滞分类。流水里两种都记，靠 amount 正负区分。 */
  readonly kind: ProgressKind | DebitKind
  readonly claimId: string
  readonly detail: string
  readonly at: number
  readonly amount: number
}

export interface GrantDecision {
  readonly granted: boolean
  readonly amount: number
  readonly reason?: string
  /** 续期后剩余。 */
  readonly remaining: number
}

export interface TimeCreditView {
  readonly started: boolean
  readonly base: number
  readonly granted: number
  /** 因停滞扣掉的额度（正数）。 */
  readonly debited: number
  readonly total: number
  readonly spent: number
  readonly remaining: number
  readonly expired: boolean
  readonly grants: readonly GrantRecord[]
}

export class TimeCredit {
  private readonly policy: TimeCreditPolicy
  private readonly now: () => number
  private startedAt: number | undefined
  private grantedMs = 0
  private debitedMs = 0
  private lastDebitAt = Number.NEGATIVE_INFINITY
  private lastGrantAt = Number.NEGATIVE_INFINITY
  private warned = false
  /** 已经发过时间的 (kind, claimId)，防止同一件事反复请款。 */
  private readonly settled = new Set<string>()
  private readonly records: GrantRecord[] = []

  constructor(policy: Partial<TimeCreditPolicy> = {}, options: { now?: () => number } = {}) {
    this.policy = { ...DEFAULT_TIME_CREDIT, ...policy }
    this.now = options.now ?? Date.now
  }

  /** 开始计时。第一次工具调用时调用；重复调用不改起点。 */
  start(at?: number): void {
    if (this.startedAt !== undefined) return
    this.startedAt = at ?? this.now()
  }

  get started(): boolean {
    return this.startedAt !== undefined
  }

  /** 总共给了多少额度（基础 + 已续期，受上限约束）。 */
  private allowance(): number {
    // 扣减直接作用在额度上，且夹在 [0, maxMs]：扣成负数没有意义，
    // 「时间到了就返回」由 remaining<=0 体现。
    return Math.max(0, Math.min(this.policy.maxMs, this.policy.baseMs + this.grantedMs - this.debitedMs))
  }

  remaining(at?: number): number {
    if (this.startedAt === undefined) return this.policy.baseMs
    return this.allowance() - ((at ?? this.now()) - this.startedAt)
  }

  expired(at?: number): boolean {
    return this.startedAt !== undefined && this.remaining(at) <= 0
  }

  /**
   * 请求续期。
   *
   * 拦三种情况：没开始计时、同一件事已经发过、冷却期内。
   * 冷却不是为了苛刻，是为了让「进展」保持稀缺——一次会话里交十条证据
   * 和交一条的认知价值可能完全一样，但时间会被刷到上限。
   */
  grant(kind: ProgressKind, claimId: string, detail: string, at?: number): GrantDecision {
    const now = at ?? this.now()
    const remainingNow = this.remaining(now)

    if (this.startedAt === undefined) {
      return { granted: false, amount: 0, reason: 'timer has not started yet', remaining: remainingNow }
    }
    const key = `${kind}:${claimId}`
    if (this.settled.has(key)) {
      return { granted: false, amount: 0, reason: `already credited for ${kind} on ${claimId}`, remaining: remainingNow }
    }
    if (now - this.lastGrantAt < this.policy.grantCooldownMs) {
      // 冷却期内不发放，但**也不记 settled**：这次不计价，不代表这件进展作废。
      // 记了 settled 会让「冷却期里交的证据」永久白交——真实推进被吞掉，
      // 而那正是这套机制唯一想奖励的东西。
      return { granted: false, amount: 0, reason: 'within grant cooldown; not credited this time', remaining: remainingNow }
    }
    if (this.allowance() >= this.policy.maxMs) {
      this.settled.add(key)
      return { granted: false, amount: 0, reason: 'credit cap reached', remaining: remainingNow }
    }

    const headroom = this.policy.maxMs - this.allowance()
    const amount = Math.min(this.policy.grantMs, headroom)
    this.grantedMs += amount
    this.lastGrantAt = now
    this.settled.add(key)
    this.records.push({ kind, claimId, detail, at: now, amount })
    return { granted: true, amount, remaining: this.remaining(now) }
  }

  /**
   * 扣时间。
   *
   * 这是奖惩里「惩」的那一半。之前只有 grant：交证据加时间，但原地打转不减。
   * 结果是「做得对会被奖励，做得不对也不会更早结束」——那不是奖惩，是单向赞助。
   *
   * 三道闸和 grant 对称：没开始计时不扣、冷却期内不重复扣、扣到上限就停。
   * 冷却尤其重要：连续停滞检测每次都会触发，不设冷却就是一口气扣穿基础额。
   */
  debit(kind: DebitKind, detail: string, at?: number): GrantDecision {
    const now = at ?? this.now()
    const remainingNow = this.remaining(now)
    if (this.startedAt === undefined) {
      return { granted: false, amount: 0, reason: 'timer has not started yet', remaining: remainingNow }
    }
    if (now - this.lastDebitAt < this.policy.debitCooldownMs) {
      return { granted: false, amount: 0, reason: 'within debit cooldown; not charged this time', remaining: remainingNow }
    }
    const headroom = this.policy.maxDebitMs - this.debitedMs
    if (headroom <= 0) {
      return { granted: false, amount: 0, reason: 'debit cap reached; further stalling does not charge more', remaining: remainingNow }
    }
    const amount = Math.min(this.policy.debitMs, headroom)
    this.debitedMs += amount
    this.lastDebitAt = now
    // 记成负的 amount：records 是同一份时间流水，正负相加就是净变化。
    this.records.push({ kind, claimId: '-', detail, at: now, amount: -amount })
    return { granted: true, amount: -amount, remaining: this.remaining(now) }
  }

  /** 已扣掉多少（正数）。 */
  get debited(): number {
    return this.debitedMs
  }

  /** 剩余时间偏低时提醒一次。 */
  shouldWarn(at?: number): boolean {
    if (this.warned) return false
    if (this.startedAt === undefined) return false
    const left = this.remaining(at)
    if (left > this.policy.warnAtMs) return false
    this.warned = true
    return true
  }

  view(at?: number): TimeCreditView {
    const now = at ?? this.now()
    const spent = this.startedAt === undefined ? 0 : now - this.startedAt
    return {
      started: this.startedAt !== undefined,
      base: this.policy.baseMs,
      granted: this.grantedMs,
      debited: this.debitedMs,
      total: this.allowance(),
      spent: Math.max(0, spent),
      remaining: this.remaining(now),
      expired: this.expired(now),
      grants: [...this.records],
    }
  }

  get policyView(): TimeCreditPolicy {
    return this.policy
  }
}

export function msToHuman(ms: number): string {
  if (ms <= 0) return '0s'
  const s = Math.round(ms / 1000)
  const m = Math.floor(s / 60)
  const rest = s % 60
  return m > 0 ? `${String(m)}m${rest === 0 ? '' : `${String(rest)}s`}` : `${String(rest)}s`
}
