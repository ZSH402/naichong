/**
 * 信誉账：把「判断准不准」变成调度排序的输入。
 *
 * 在这之前，误报账本（precision）和战绩档案（roster）都只记录、不参与决策。
 * 那条边界当初是对的：样本量小时统计不可信，让一次偶发失败自动降权，会把
 * 「今天网络抖了一下」固化成「这个工具永远排最后」。但只记不用的另一个代价是
 * **系统不会因为反复报错而改变行为**——同一个最容易误报的牌，每轮都还会被先派出去。
 *
 * ── 两个信号，别混在一起 ──────────────────────────────
 *
 *   准确率（本模块）  —— 它报的发现后来被推翻了吗。衡量**判断**。
 *   执行率（roster）  —— 它跑起来了吗、给了结论吗。衡量**可用性**。
 *
 * 执行失败已经有自己的处理路径（faultCircuit 熔断、registry 的冷却、probe 的 missing），
 * 不能再混进信誉分：一个工具可以每次都跑成功但报的全是误报，也可以很少跑但每次都对。
 * 把两件事揉成一个数字，会让「跑不动」和「老报错」看起来一样，而它们的修法完全不同。
 *
 * ── 为什么用 Beta 后验而不是比率 ──────────────────────
 *
 * 朴素比率 `confirmed / sample` 是小样本陷阱：1 次成功就是 100%，会被排到
 * 100 次里成功 90 次的老牌前面。（这正是 Reddit 当年放弃 upvote ratio、
 * 改用 Wilson 下界的原因：1/1 的 100% 在 Wilson 下界下只有 0.378。）
 *
 * 但 Wilson 在 n=0 时返回 0，对我们的场景是个硬伤：**没跑过的牌会被排到最后，
 * 永远轮不到，也就永远拿不到样本**。所以这里用 Beta 先验：
 *
 *   Beta(1 + confirmed, 1 + refuted) 的均值
 *
 *   没跑过        → (0+1)/(0+0+2) = 0.500   中性，既不奖也不罚
 *   1 次成功      → 2/3 = 0.667
 *   1 次失败      → 1/3 = 0.333            一次失手只压 0.17，不毁灭
 *   5 次成功      → 6/7 = 0.857
 *   5 次失败      → 1/7 = 0.143
 *
 * 那个 +1/+1 的先验不是凑数：它就是**惩罚的地板**。一条被冤枉的记录只能把分数
 * 从 0.5 拉到 0.333；后来成功几次就自己回升了。信誉系统的共识是「坏消息比好消息
 * 更可信」，所以非对称确实常见；但在这里非对称换来的那点灵敏度，代价是
 * 「一次误判毁掉一张好牌」——而我们每轮只有几次派活额度，毁一张牌很贵。
 *
 * ── 为什么还要探索项 ─────────────────────────────────
 *
 * 光有后验均值会让系统早熟：一旦某张牌攒到 0.85，就再也不会去试别的，
 * 而环境是会变的（模板过期、目标换了形态）。用 UCB1 的探索项补上：
 *
 *   explore = weight * sqrt(ln(总执行次数 + 1) / (该牌执行次数 + 1))
 *
 * 跑得少的牌加分多。分母 +1 是为了让「没跑过」有一个确定的有限值，
 * 而不是无穷大（那是经典 UCB1 的边界问题）。
 *
 * 最终：value = clamp(posterior + explore, FLOOR, CEIL)
 *
 * 实测一组数（总执行 100 次、weight 0.15）：
 *
 *   5 次全成功  0.857 + 0.132 = 0.98（封顶）
 *   1 次成功    0.667 + 0.228 = 0.90
 *   没跑过      0.500 + 0.322 = 0.82
 *   1 次失败    0.333 + 0.228 = 0.56
 *   5 次全失败  0.143 + 0.132 = 0.28
 *
 * 这个序就是想要的：赢过的在前，没试过的还有机会，失过手的往后但不除名。
 */

import type { Claim } from '../provenance.ts'
import { agentsOfClaim } from './precision.ts'
import type { Roster } from './roster.ts'

/** 中性值：没跑过的牌拿这个分，排序上既不加分也不减分。 */
export const CREDIT_NEUTRAL = 0.5
/** 下限。再差的牌也保留一点机会——完全清零等于永久弃用，而误报常常是解析器的错。 */
export const CREDIT_FLOOR = 0.05
/** 上限。留出余量，避免「满分」让探索项再也翻不动它的位置。 */
export const CREDIT_CEIL = 0.98

export interface CreditOptions {
  /** 探索权重。0 表示纯利用（不推荐：会早熟）。 */
  readonly exploreWeight?: number
  /**
   * 命中率通道的权重（0..1）。0 = 只看准确率。
   *
   * 准确率信号强但**稀疏且迟到**：一条 claim 要到 confirmed 需要两条独立强路径，
   * 而一次渗透结束时大部分 claim 还挂在 partial。现实结果是跑十次派活一个定论
   * 都没有，所有牌永远停在 0.5——机制等于没做。
   *
   * 命中率是另一个通道，回答的是「它跑出来的东西和这条断言有关系吗」，
   * 每次 attach 就有信号（相关性闸给出 strong/weak），样本密、来得快，但弱：
   * 相关不等于对。所以给它小权重，让它在冷启动期提供早期方向，
   * 定论一多就被准确率盖过去。
   */
  readonly hitWeight?: number
  /**
   * 战绩半衰期（毫秒）。0 表示不衰减。
   *
   * 衰减解决的是「三年前的战绩和昨天的一样重」：模板会过期、目标会换形态、
   * 上游工具会改判据，一份永不过期的准确率会让系统对着一个已经不存在的世界调参。
   *
   * 不需要额外存事件流——claim 自带 `updatedAt`，逐条按年龄加权就是衰减。
   * 这也是「现算不落盘」这条设计还能继续成立的原因。
   */
  readonly halfLifeMs?: number
}

/** 默认半衰期：90 天。一次渗透周期内基本不衰减，跨季度会开始淡出。 */
export const DEFAULT_HALF_LIFE_MS = 90 * 24 * 60 * 60 * 1000

/**
 * 一条定论在「现在」还剩多少权重。
 *
 * 指数遗忘，半衰期式：过了半个半衰期剩 0.707，过一个剩 0.5，过两个剩 0.25。
 * 用平滑衰减而不是「只看最近 N 条」，是因为窗口边界会让一次刚好落在窗口外的
 * 失败完全消失，而平滑衰减至少还留着一点痕迹。
 */
export function recencyWeight(settledAt: number, now: number, halfLifeMs: number): number {
  if (!(halfLifeMs > 0)) return 1
  const age = Math.max(0, now - settledAt)
  return Math.pow(0.5, age / halfLifeMs)
}

export interface CreditScore {
  readonly agent: string
  /** 排序用的最终值，落在 [FLOOR, CEIL]。 */
  readonly value: number
  /** Beta 后验均值：只反映判断准不准。 */
  readonly posterior: number
  /** 探索加成：只反映跑得少。 */
  readonly explore: number
  /** 原始计数（整数，给人看）。 */
  readonly confirmed: number
  readonly refuted: number
  /** 按年龄加权后的计数（浮点，算分用）。陈旧战绩在这里是打折的。 */
  readonly effectiveConfirmed: number
  readonly effectiveRefuted: number
  /** effectiveConfirmed + effectiveRefuted。后验的样本量。 */
  readonly sample: number
  /** 原始样本量（不衰减），用来区分「从没有证据」和「证据都过期了」。 */
  readonly rawSample: number
  /** 相关性闸判为 strong 的证据条数（加权后）。 */
  readonly strong: number
  /** 相关性闸判为 weak 的证据条数（加权后）：跑了，但产出没触及断言。 */
  readonly weak: number
  /** 命中率后验：strong vs weak。没有证据时为中性。 */
  readonly hitPosterior: number
  /** 执行次数（来自 roster），只进探索项。 */
  readonly runs: number
  /** 为什么是这个分。 */
  readonly basis: string
}

/**
 * Beta(1+c, 1+r) 的均值。
 *
 * 先验强度取 1（相当于「一开始假设它对过一次也错过一次」）。取更大（比如 5）
 * 会让可信区间更宽、惩罚更慢，冷启动期几乎看不出差别；取 1 是恰好让
 * 一次成功/失败移动约 0.17 的力度——够看得出来，又不至于一锤定音。
 */
export function betaPosterior(confirmed: number, refuted: number): number {
  return (confirmed + 1) / (confirmed + refuted + 2)
}

/** UCB1 式探索项。跑得越少加得越多；分母 +1 让没跑过也有有限值。 */
export function exploreBonus(runs: number, totalRuns: number, weight: number): number {
  if (weight <= 0) return 0
  return weight * Math.sqrt(Math.log(totalRuns + 1) / (runs + 1))
}

function clamp(x: number, lo: number, hi: number): number {
  return x < lo ? lo : x > hi ? hi : x
}

/** 单张牌的得分。 */
export function creditScore(
  input: {
    readonly agent: string
    readonly confirmed: number
    readonly refuted: number
    readonly runs: number
    /** 加权后的计数。省略时等于原始计数（不衰减）。 */
    readonly effectiveConfirmed?: number
    readonly effectiveRefuted?: number
    /** 相关性证据的加权计数。省略表示没有相关性数据。 */
    readonly strong?: number
    readonly weak?: number
  },
  totalRuns: number,
  options: CreditOptions = {},
): CreditScore {
  const weight = options.exploreWeight ?? 0.15
  const effC = input.effectiveConfirmed ?? input.confirmed
  const effR = input.effectiveRefuted ?? input.refuted
  const accuracy = betaPosterior(effC, effR)
  const strong = input.strong ?? 0
  const weak = input.weak ?? 0
  const hitPosterior = betaPosterior(strong, weak)
  // 两通道加权混合。命中率的权重默认 0.3：它比准确率弱一个量级，
  // 但比「什么都还不知道」强——冷启动期它就是唯一的信号。
  //
  // 但**没有相关性数据时权重必须归零**：Beta(1,1) 的中性先验不等于「有信息」，
  // 拿它去稀释准确率，等于让一个什么都不知道的通道投反对票。
  // 表现出来就是「一条 400 天前的旧失败把分数从 0.74 拉到 0.67」——
  // 而那个变化和命中率毫无关系。
  const configuredHitWeight = Math.min(1, Math.max(0, options.hitWeight ?? 0.3))
  const hitWeight = strong + weak === 0 ? 0 : configuredHitWeight
  const posterior = (1 - hitWeight) * accuracy + hitWeight * hitPosterior
  const explore = exploreBonus(input.runs, totalRuns, weight)
  const value = clamp(posterior + explore, CREDIT_FLOOR, CREDIT_CEIL)
  const sample = effC + effR
  const rawSample = input.confirmed + input.refuted
  const decayed = rawSample > 0 && sample < rawSample - 1e-9
  // 权重显示成 2 位有效小数：0.046 被 toFixed(1) 抹成 0.0 会让人以为那条记录删掉了，
  // 而它其实还在，只是很轻。
  const fmt = (x: number): string => (x === 0 ? '0' : x < 0.1 ? x.toFixed(3) : x.toFixed(2))
  const counts = `${String(input.confirmed)} confirmed / ${String(input.refuted)} refuted${
    decayed ? ` (aged to ${fmt(effC)}/${fmt(effR)})` : ''
  }`
  const channel =
    hitWeight === 0
      ? ''
      : ` [accuracy ${accuracy.toFixed(2)}×${(1 - hitWeight).toFixed(2)} + relevance ${hitPosterior.toFixed(2)}(${strong.toFixed(1)}/${weak.toFixed(1)})×${hitWeight.toFixed(2)}]`
  const basis =
    rawSample === 0 && strong + weak === 0
      ? `no evidence yet (runs=${String(input.runs)}) — neutral prior ${posterior.toFixed(3)} + explore ${explore.toFixed(3)}`
      : `${rawSample === 0 ? 'no settled claim yet' : counts}${channel} — posterior ${posterior.toFixed(3)} + explore ${explore.toFixed(3)}`
  return {
    agent: input.agent,
    value,
    posterior,
    explore,
    confirmed: input.confirmed,
    refuted: input.refuted,
    effectiveConfirmed: effC,
    effectiveRefuted: effR,
    sample,
    rawSample,
    strong,
    weak,
    hitPosterior,
    runs: input.runs,
    basis,
  }
}

/**
 * 从「已定论的 claim」里数出每张牌的胜负。
 *
 * 三个口径和 precision 保持一致，否则同一个事实会出现两个不同的数：
 *
 *   一、按 claim 计数不按执行次数：同一张牌跑三次产出的证据挂在一条 claim 上，
 *       那是一次判断，不是三次。
 *   二、只统计**有归因**的推翻：一条 claim 常挂着几个工具的证据，被推翻时
 *       未必每个都错。没归因就不记黑账——宁可样本少，不要错归因。
 *   三、分母只算已定论：还挂在 hypothesis / partial 的 claim 既没被证实也
 *       没被推翻，算进来会把这个工具的准确率稀释成好看的样子。
 */
export interface VerdictTally {
  readonly confirmed: number
  readonly refuted: number
  /** 按年龄加权后的计数。不衰减时等于原始计数。 */
  readonly effectiveConfirmed: number
  readonly effectiveRefuted: number
}

export function tallyVerdicts(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number } = {},
): Map<string, VerdictTally> {
  return tallyWith(claims, options, (agent) => agent)
}

/**
 * 按「工具 + 目标形态」分层统计。
 *
 * key 形如 `nuclei@url`。同一张牌在不同形态上的表现可以完全不同——nuclei 对 url
 * 准、对 directory 基本没用——不分层就是把这些差异平均掉，而平均出来的数字
 * 对任何具体场景都不适用。
 *
 * 没有 shape 的 claim（模型自己 assert 的、或者历史数据）只进 agent 级，
 * 不进任何形态桶：把未知形态塞进某个桶里，等于凭空造出一条证据。
 */
export function tallyByShape(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number } = {},
): Map<string, VerdictTally> {
  return tallyWith(claims, options, (agent, shape) => (shape === undefined ? undefined : `${agent}@${shape}`))
}

/** 形态级统计至少要这么多条定论才用它。低于这个数就退回 agent 级。 */
export const MIN_SHAPE_SAMPLE = 3

/** 相关性计数：这条证据是推进了断言，还是只是跑了。 */
export interface RelevanceTally {
  readonly strong: number
  readonly weak: number
}

/**
 * 按工具统计「产出与断言的相关性」。
 *
 * strong = 执行内容真的触及了断言的锚点；weak = 跑了，但产出跟这条断言没关系。
 * 这是唯一一类**每次 attach 就能拿到**的反馈——不像准确率要等定论。
 * 手工证据（没有 relevance 字段）不计：不知道它相关不相关，不能当弱点也不能当强点。
 * control 证据（检测器校准）也不计：它跑的是本地样本，不是这次的目标。
 */
export function tallyRelevance(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number } = {},
): Map<string, RelevanceTally> {
  return relevanceWith(claims, options, (agent) => agent)
}

/** 按「工具 + 形态」分层的相关性计数。 */
export function tallyRelevanceByShape(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number } = {},
): Map<string, RelevanceTally> {
  return relevanceWith(claims, options, (agent, shape) => (shape === undefined ? undefined : `${agent}@${shape}`))
}

function relevanceWith(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number },
  keyOf: (agent: string, shape?: string) => string | undefined,
): Map<string, RelevanceTally> {
  const now = options.now ?? Date.now()
  const halfLife = options.halfLifeMs ?? 0
  const acc = new Map<string, RelevanceTally>()
  for (const claim of claims) {
    const weight = recencyWeight(claim.updatedAt ?? now, now, halfLife)
    for (const e of claim.evidence) {
      if (e.role === 'control') continue
      const strength = e.relevance?.strength
      if (strength === undefined) continue
      const tool = e.source?.argv[0]
      if (typeof tool !== 'string' || tool === '') continue
      const agent = tool.split('/').pop() ?? tool
      const k = keyOf(agent, claim.shape)
      if (k === undefined) continue
      const a = acc.get(k) ?? { strong: 0, weak: 0 }
      acc.set(k, {
        strong: a.strong + (strength === 'strong' ? weight : 0),
        weak: a.weak + (strength === 'weak' ? weight : 0),
      })
    }
  }
  return acc
}

function tallyWith(
  claims: readonly Claim[],
  options: { readonly now?: number; readonly halfLifeMs?: number },
  keyOf: (agent: string, shape?: string) => string | undefined,
): Map<string, VerdictTally> {
  const now = options.now ?? Date.now()
  const halfLife = options.halfLifeMs ?? 0
  const acc = new Map<string, VerdictTally>()
  const bump = (agent: string, shape: string | undefined, key: 'confirmed' | 'refuted', weight: number): void => {
    const k = keyOf(agent, shape)
    if (k === undefined) return
    const a = acc.get(k) ?? { confirmed: 0, refuted: 0, effectiveConfirmed: 0, effectiveRefuted: 0 }
    const next: VerdictTally = {
      confirmed: a.confirmed + (key === 'confirmed' ? 1 : 0),
      refuted: a.refuted + (key === 'refuted' ? 1 : 0),
      effectiveConfirmed: a.effectiveConfirmed + (key === 'confirmed' ? weight : 0),
      effectiveRefuted: a.effectiveRefuted + (key === 'refuted' ? weight : 0),
    }
    acc.set(k, next)
  }
  for (const claim of claims) {
    const agents = agentsOfClaim(claim)
    if (agents.length === 0) continue
    // 衰减锚点是这条断言定论的时间；没有 updatedAt 的历史数据按「现在」算，即不打折。
    const weight = recencyWeight(claim.updatedAt ?? now, now, halfLife)
    if (claim.status === 'confirmed') {
      for (const agent of agents) bump(agent, claim.shape, 'confirmed', weight)
      continue
    }
    if (claim.status !== 'refuted') continue
    const blamed = new Set((claim.blame ?? []).map((b) => b.split('/').pop() ?? b))
    if (blamed.size === 0) continue
    for (const agent of agents) {
      // 只记被明确点名的。没被点名说明它的证据仍然成立，只是这条断言本身错了。
      if (blamed.has(agent)) bump(agent, claim.shape, 'refuted', weight)
    }
  }
  return acc
}

/**
 * 信誉面板：调度排序用的查询入口。
 *
 * 现算不落盘——多存一份账本，就多一处会和真相脱节的地方（和 precision 同一个理由）。
 * `refresh` 由每轮编排开始时调用一次；排序路径上只做 Map 查询。
 */
export class CreditBoard {
  private scores = new Map<string, CreditScore>()
  private shapeScores = new Map<string, CreditScore>()
  private readonly options: CreditOptions
  private readonly clock: () => number

  /**
   * 取最新 claims 的方式。
   *
   * 存**取数函数**而不是数组快照：`ClaimStore.query()` 每次都返回新数组，
   * 缓存一份旧快照再重算，算出来还是同一份旧数据——版本号检查会通过，
   * 但答案永远是开天辟地那一刻的。这个错误不会报错，只会让「一轮内学习」静默失效。
   */
  private fetchClaims: (() => readonly Claim[]) | undefined
  private lastRoster: Roster | undefined
  private sourceVersion = -1
  private readonly versionOf: (() => number) | undefined

  constructor(
    options: CreditOptions & {
      readonly now?: () => number
      readonly versionOf?: () => number
      readonly fetchClaims?: () => readonly Claim[]
    } = {},
  ) {
    this.options = options
    this.clock = options.now ?? Date.now
    this.versionOf = options.versionOf
    this.fetchClaims = options.fetchClaims
  }

  /**
   * 数据变了就重算，没变什么都不做。
   *
   * 这是「一轮之内也要学习」的实现：原来只在 council.run 开头刷一次，
   * 于是一轮里派了五次活、第三次已经证明某张牌不可靠了，剩下两次仍按旧数据排。
   * 挂到查询路径上之后，第一条定论落库的瞬间，下一次排序就看得见它。
   *
   * 不做事件订阅：漏一个事件只表现为「数字旧了一点」，而版本号最多滞后到下一次查询。
   */
  private refreshIfStale(): void {
    if (this.versionOf === undefined) return
    if (this.versionOf() === this.sourceVersion) return
    if (this.fetchClaims === undefined) return
    this.refresh(this.fetchClaims(), this.lastRoster)
  }

  private now(): number {
    return this.clock()
  }

  /** 重算全部得分。claims 变了就该调一次。 */
  refresh(claims: readonly Claim[], roster?: Roster): void {
    const decay = { now: this.now(), halfLifeMs: this.options.halfLifeMs ?? 0 }
    const tally = tallyVerdicts(claims, decay)
    const byShape = tallyByShape(claims, decay)
    const relevance = tallyRelevance(claims, decay)
    const relevanceByShape = tallyRelevanceByShape(claims, decay)
    const runCounts = new Map<string, number>()
    let totalRuns = 0
    for (const rec of roster?.view() ?? []) {
      runCounts.set(rec.id, rec.runs)
      totalRuns += rec.runs
    }
    const zero = { confirmed: 0, refuted: 0, effectiveConfirmed: 0, effectiveRefuted: 0 }
    const build = (agent: string, t: VerdictTally, rel: RelevanceTally | undefined, runs: number): CreditScore =>
      creditScore(
        {
          agent,
          confirmed: t.confirmed,
          refuted: t.refuted,
          effectiveConfirmed: t.effectiveConfirmed,
          effectiveRefuted: t.effectiveRefuted,
          strong: rel?.strong ?? 0,
          weak: rel?.weak ?? 0,
          runs,
        },
        totalRuns,
        this.options,
      )

    const next = new Map<string, CreditScore>()
    for (const agent of new Set<string>([...tally.keys(), ...runCounts.keys(), ...relevance.keys()])) {
      next.set(agent, build(agent, tally.get(agent) ?? zero, relevance.get(agent), runCounts.get(agent) ?? 0))
    }
    const nextShape = new Map<string, CreditScore>()
    for (const key of new Set<string>([...byShape.keys(), ...relevanceByShape.keys()])) {
      // 形态级的 runs 没有来源（roster 不分形态），给 0：这一层不做探索加成，
      // 探索是「这张牌整体跑得少不少」，全局已经算过一次了。
      nextShape.set(
        key,
        build(key, byShape.get(key) ?? zero, relevanceByShape.get(key), 0),
      )
    }
    this.scores = next
    this.shapeScores = nextShape
    this.totalRuns = totalRuns
    // roster 可以只传一次：它的变化路径单一（每次编排结束 persist），
    // claims 才是会在一轮之内反复变的那一侧。
    if (roster !== undefined) this.lastRoster = roster
    this.sourceVersion = this.versionOf?.() ?? this.sourceVersion
  }

  private totalRuns = 0

  /**
   * 某张牌的得分。没记录的一律按中性处理——没试过不等于不行。
   *
   * 给了 shape 时：该形态上的定论够 MIN_SHAPE_SAMPLE 条就用形态级的，
   * 否则退回全局。形态级样本少时，它反映的是「在这个形态上碰巧发生了什么」，
   * 而不是「它在这个形态上是否可靠」——用回全局至少样本更多。
   */
  scoreOf(agent: string, shape?: string): CreditScore {
    this.refreshIfStale()
    if (shape !== undefined) {
      const s = this.shapeScores.get(`${agent}@${shape}`)
      // 定论不够但相关性样本够，也该用形态级：那正是命中率通道存在的意义
      // （在还没有任何定论时就能给出方向）。
      const enough = s !== undefined && (s.rawSample >= MIN_SHAPE_SAMPLE || s.strong + s.weak >= MIN_SHAPE_SAMPLE)
      if (enough) return s
    }
    return (
      this.scores.get(agent) ??
      creditScore({ agent, confirmed: 0, refuted: 0, runs: 0 }, this.totalRuns, this.options)
    )
  }

  /** 形态级得分，只返回样本够的那些。用于报告「这个形态上谁被压后了」。 */
  shapeView(): CreditScore[] {
    return [...this.shapeScores.values()]
      .filter((s) => s.rawSample >= MIN_SHAPE_SAMPLE || s.strong + s.weak >= MIN_SHAPE_SAMPLE)
      .sort((a, b) => b.value - a.value)
  }

  /**
   * 有效优先级 = 作者给的优先级 × (中性 / 信誉)。
   *
   * 用乘性修正而不是直接拿信誉当排序键，是为了保住作者经验里的量级关系：
   * 中性牌（0.5）优先级不变；信誉 0.85 的牌提前约 1.7 倍；信誉 0.14 的牌
   * 后退约 3.5 倍。这样「nuclei 比 strix 优先」这类判断在没数据时依然成立，
   * 而一旦某张牌反复出错，它自己会沉下去。
   *
   * 直接按信誉绝对值排序的坏处：它会把「快而略糙」和「慢而准」压成同一个维度，
   * 而这两者的取舍是作者已经用 priority 表达过的意见。
   */
  effectivePriority(agent: string, priority: number, shape?: string): number {
    const credit = this.scoreOf(agent, shape).value
    return priority * (CREDIT_NEUTRAL / credit)
  }

  all(): CreditScore[] {
    return [...this.scores.values()].sort((a, b) => b.value - a.value)
  }
}
