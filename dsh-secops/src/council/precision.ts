/**
 * 误报账本：哪个工具报的发现，后来被推翻了。
 *
 * 这套系统的证据链能验证「证据相关」和「证据可复现」，验证不了「结论正确」——
 * 严格摘要重放保证的是重跑得到同样输出，不是这个输出说明有问题。
 * 在引入独立仲裁者之前，唯一能积累的客观信号就是：**被推翻的比例**。
 *
 * 口径上三件事必须算清楚，否则这个数字会骗人：
 *
 *   一、按 claim 计数，不按执行次数。同一个工具跑三次产出的证据挂在一条 claim 上，
 *       它只该算一次判断，不是三次。
 *
 *   二、只统计**有归因**的推翻。一条 claim 常挂着多个工具的证据，被推翻时未必
 *       每个都错。没有明确归因就不记黑账——宁可样本少，不要错归因。
 *
 *   三、分母是「已定论」，不是「所有报告」。还挂在 hypothesis / partial 的 claim
 *       既没被证实也没被推翻，把它算进分母会把误报率稀释成好看的样子。
 */

import type { Claim } from '../provenance.ts'

/** 低于这个样本量不给比率：三条里错一条不是 33%，是样本不够。 */
export const MIN_SAMPLE = 5

export interface AgentPrecision {
  readonly agent: string
  /** 作为证据来源支持过多少条 claim。 */
  readonly reported: number
  readonly confirmed: number
  /** 被归因推翻的次数。 */
  readonly refuted: number
  /** 还没有定论的（hypothesis / partial）。 */
  readonly open: number
  /** confirmed + refuted。比率的分母。 */
  readonly sample: number
  /** refuted / sample；样本不足时为 undefined。 */
  readonly falsePositiveRate?: number
  /** 为什么没有比率，或者这个比率该打几折看。 */
  readonly note?: string
}

export interface PrecisionReport {
  readonly agents: readonly AgentPrecision[]
  /** 被推翻但没有归因的 claim 数——它们是统计不到的真实误报。 */
  readonly unattributedRefutations: number
  readonly totalClaims: number
  readonly settledClaims: number
}

/** 从一条 claim 的证据里取出工具名集合。手工证据（无 source）不参与。 */
export function agentsOfClaim(claim: Claim): string[] {
  const set = new Set<string>()
  for (const e of claim.evidence) {
    const tool = e.source?.argv[0]
    if (typeof tool === 'string' && tool.length > 0) set.add(baseName(tool))
  }
  return [...set]
}

function baseName(p: string): string {
  const i = p.lastIndexOf('/')
  return i === -1 ? p : p.slice(i + 1)
}

/**
 * 汇总所有 claim，算出每个工具的误报率。
 *
 * 纯函数，从现有数据现算——不额外维护一份账本。
 * 多一份账本就多一处会与真相脱节的地方。
 */
export function analyzePrecision(claims: readonly Claim[]): PrecisionReport {
  interface Acc {
    reported: number
    confirmed: number
    refuted: number
    open: number
  }
  const acc = new Map<string, Acc>()
  let unattributed = 0
  let settled = 0

  for (const claim of claims) {
    const agents = agentsOfClaim(claim)
    const isRefuted = claim.status === 'refuted'
    const isConfirmed = claim.status === 'confirmed'
    if (isRefuted || isConfirmed) settled += 1

    if (isRefuted) {
      const blamed = claim.blame ?? []
      if (blamed.length === 0) unattributed += 1
    }

    for (const agent of agents) {
      const a = acc.get(agent) ?? { reported: 0, confirmed: 0, refuted: 0, open: 0 }
      a.reported += 1
      if (isConfirmed) a.confirmed += 1
      else if (isRefuted) {
        // 只有明确归因到这个工具时才记它一笔
        if ((claim.blame ?? []).includes(agent) || (claim.blame ?? []).includes(baseName(agent))) a.refuted += 1
        else a.open += 1
      } else {
        a.open += 1
      }
      acc.set(agent, a)
    }
  }

  const agents: AgentPrecision[] = [...acc.entries()]
    .map(([agent, a]) => {
      const sample = a.confirmed + a.refuted
      const base: AgentPrecision = {
        agent,
        reported: a.reported,
        confirmed: a.confirmed,
        refuted: a.refuted,
        open: a.open,
        sample,
      }
      if (sample === 0) {
        return { ...base, note: 'no settled claim yet — nothing to score' }
      }
      if (sample < MIN_SAMPLE) {
        return { ...base, note: `sample ${sample} < ${MIN_SAMPLE}; a ratio here would be noise` }
      }
      return { ...base, falsePositiveRate: a.refuted / sample }
    })
    // 样本够的排前面，再按误报率降序——最该被审视的排最上面
    .sort((a, b) => {
      const as = a.falsePositiveRate === undefined ? -1 : a.falsePositiveRate
      const bs = b.falsePositiveRate === undefined ? -1 : b.falsePositiveRate
      if (as !== bs) return bs - as
      return b.sample - a.sample
    })

  return {
    agents,
    unattributedRefutations: unattributed,
    totalClaims: claims.length,
    settledClaims: settled,
  }
}

/**
 * 把误报账本翻译成可执行的话。
 *
 * 只提示，不自动弃用：样本刚够就开始拉黑一个工具，等于用五条数据决定一个长期决策。
 * 而且误报常常不是工具的错——目标页本身就是测试页、模板过期、解析器有 bug。
 * 提示人去查，比系统自己下结论可靠。
 */
export function precisionActions(report: PrecisionReport, options: { readonly threshold?: number } = {}): string[] {
  const threshold = options.threshold ?? 0.3
  const actions: string[] = []

  const worst = report.agents.filter((a) => a.falsePositiveRate !== undefined && a.falsePositiveRate >= threshold)
  if (worst.length > 0) {
    actions.push(
      `${worst.map((a) => `${a.agent}(${Math.round((a.falsePositiveRate ?? 0) * 100)}%)`).join(', ')} 的误报率达到阈值：` +
        `优先查它们的判据（verdict 解析器 / 模板是否过期），而不是直接弃用——误报常常是解析器的错，不是工具的错`,
    )
  }

  if (report.unattributedRefutations > 0) {
    actions.push(
      `有 ${report.unattributedRefutations} 条 claim 被推翻但没记归因；这部分误报统计不到，` +
        `下次 claim_refute 时用 blame_agent 指明是哪个工具的证据不可靠`,
    )
  }

  const noSample = report.agents.filter((a) => a.falsePositiveRate === undefined && a.reported > 0)
  if (noSample.length > 0 && report.settledClaims < MIN_SAMPLE) {
    actions.push(
      `目前只有 ${report.settledClaims} 条 claim 有了定论，误报率还不能用；` +
        `继续积累到 ${MIN_SAMPLE} 条再看，在此之前别凭印象换工具`,
    )
  }

  return actions
}
