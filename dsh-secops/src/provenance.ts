/**
 * Provenance：知识点级的断言与证据归属。
 *
 * 与 OpenClaw 的 memory provenance 的关键区别：
 *   OpenClaw 判据是「turn 被网络工具结果污染 → untrusted」。
 *   安全测试的证据**全部**来自网络，照搬会让一切不可信，系统直接瘫痪。
 *
 * 这里的判据是**独立复现次数**：
 *   一条断言要升为「已验证事实」，必须有 ≥2 条来源独立的证据。
 *   独立性由调用方声明 `pathKey`（例如 "http:differential" / "tool:recompute" /
 *   "role:other-user"），同一 pathKey 的多条证据只算一条路径。
 *   这直接对应「同一事实需要两条不同路径才能确认」的方法论。
 *
 * 四状态与项目摘要 §8 一一对应：
 *   hypothesis      → 待验证假设（有迹象）
 *   partial         → 待验证假设（已有部分证据，未达独立阈值）
 *   confirmed       → 已验证事实（≥2 条独立路径）
 *   refuted         → 已证伪路径（无新证据不重复派发）
 *
 * 额外保留 inference：Agent 推断，明确标注为模型解释而非观测。
 */

import { createHash } from 'node:crypto'
import { z } from 'zod'
import { appendPluginRecord, pluginRecordOf, type Session } from '@deepseek-ai/dsh-session'
import type { SessionEvent } from '@deepseek-ai/dsh-session'

export const claimStatusSchema = z.enum(['hypothesis', 'partial', 'confirmed', 'refuted', 'inference'])
export type ClaimStatus = z.infer<typeof claimStatusSchema>

const relevanceSchema = z.object({
  /** strong = 执行内容覆盖锚点；weak = 仅声明覆盖。 */
  strength: z.enum(['strong', 'weak']),
  /** 命中的锚点，形如 "path:/api/user"。 */
  matched: z.array(z.string()),
})

/** 证据的来源信息 —— 有它才能重放。 */
const evidenceSourceSchema = z.object({
  kind: z.literal('worker'),
  taskId: z.string(),
  argv: z.array(z.string()),
  cwd: z.string(),
})

/** 一次重放的结果。 */
const replaySchema = z.object({
  /** 重放后骨架摘要与原产物一致，且退出码正常。 */
  verified: z.boolean(),
  at: z.number(),
  exitCode: z.number().nullable(),
  digest: z.string(),
  /** strict = 数值也一致；structural = 仅结构一致；none = 不一致。 */
  matchKind: z.enum(['strict', 'structural', 'none']).optional(),
  reason: z.string().optional(),
})

const evidenceSchema = z.object({
  /** 证据引用：文件路径、证据 id、请求哈希等。 */
  ref: z.string(),
  /** 独立性键。同一 pathKey 的多条证据只算一条独立路径。 */
  pathKey: z.string(),
  /** 可选说明。 */
  note: z.string().optional(),
  /** 调用方声明的「这条证据观测到了什么」，用于相关性核对。 */
  observed: z.string().optional(),
  /** 相关性判定结果。缺省表示登记时未校验（历史数据）。 */
  relevance: relevanceSchema.optional(),
  /**
   * 这条证据在论证里扮演什么角色。
   *
   * proof     —— 证明问题存在（越权读到了别人的数据、注入成功回显）
   * baseline  —— **目标**的正常情况对照（同一接口用正常参数返回正常结果）
   * control   —— **检测器**的对照：拿一个已知结论的样本跑同一条命令，它必须给出
   *              已知的那个结论。校准的是工具，不是目标。
   *
   * 为什么必须分开：只说「越权访问成功了」而不给「正常请求长什么样」，
   * 复核者无法判断这是真的越权还是接口本来就这么返回。
   *
   * 为什么 control 不能并进 baseline：二进制加固检查（这货缺不缺 canary）、
   * TLS 配置这类目标**根本没有「正常情况」可比**——你没法让同一个二进制
   * 「加固着」当对照。能证明的只剩「检测方法可信」：`checksec` 在加固齐全的
   * 发行版 ls 上必须报 clean。它要是也报缺，那问题在检测器或环境。
   * 把这两件事塞进同一个 role，等于用「工具可信」冒充「目标已对照」。
   */
  role: z.enum(['proof', 'baseline', 'control', 'refutation']).optional(),
  /**
   * 反驳的明细。只在 role='refutation' 时有意义。
   *
   * kind 的两档是这套机制里最重要的一个区分：
   *
   *   decisive —— **可以据此直接判死**：符号没有任何调用方（死代码）、
   *               路由从未注册、实测请求打不通、守卫在目标路径上确定生效。
   *   advisory —— **只降级不下结论**："在上游找到疑似守卫，但是否覆盖这条路径
   *               需要人判断"。这类不能自动翻转状态。
   *
   * 为什么必须分开：把真漏洞反驳掉（漏报）比报一条误报更糟。Refute-or-Promote
   * 的实证里，10 个专职审查员一致认可的漏洞只被一条实证测试击毙——说明
   * "看起来足以否定"和"足以否定"之间差着一次实证。advisory 是给模型和人的
   * 线索，不是判决书。
   */
  refutation: z
    .object({
      kind: z.enum(['decisive', 'advisory']),
      /** 哪个检查项得出的（dead-code / unreachable-route / guard-found / empirical-miss …）。 */
      check: z.string(),
      /** 事实出处：file:line，便于复核。 */
      location: z.string().optional(),
      /** 一句话说明看到了什么。 */
      detail: z.string().optional(),
    })
    .optional(),
  /** 来源（worker 任务），用于重放。手工证据没有这项。 */
  source: evidenceSourceSchema.optional(),
  /** 原产物的结构摘要（抹数字）。 */
  baselineDigest: z.string().optional(),
  /** 原产物的严格摘要（保留数字），重放时优先用它判 strict。 */
  baselineStrictDigest: z.string().optional(),
  /** 最近一次重放结果。 */
  replay: replaySchema.optional(),
  addedAt: z.number(),
})

export type Evidence = z.infer<typeof evidenceSchema>

export const claimSchema = z.object({
  id: z.string(),
  /** 可证伪的陈述，不是漏洞类别名。 */
  claim: z.string(),
  status: claimStatusSchema,
  /** 证伪条件：什么样的观测会推翻它。 */
  falsifier: z.string().optional(),
  evidence: z.array(evidenceSchema),
  /** 独立路径数（pathKey 去重后的数量）。 */
  independentPaths: z.number(),
  /**
   * 证伪归因：是哪几个工具（agent）产出的证据被推翻了。
   *
   * 刻意允许为空。没写明时**不归因**，只记这条 claim 被推翻——
   * 一条 claim 常挂着多个工具的证据，被推翻时未必每个都错。
   * 把所有人一起记黑账，会让准确的那个也跟着背锅，这种"保守"是错的保守。
   */
  blame: z.array(z.string()).optional(),
  /**
   * 这条断言涉及哪些资产。
   *
   * 借鉴 ARTEX 的 `findings.asset_ids`：一个发现可能横跨多个资产
   * （比如同一份密钥出现在两台主机上）。用数组而不是单值。
   */
  assetIds: z.array(z.string()).optional(),
  /**
   * 这条断言是在哪种目标形态下产生的（url / binary / directory / host …）。
   *
   * 存在的理由是信誉要分层：同一张牌在不同形态上的表现可以完全不同
   * （nuclei 对 url 准，对 directory 基本没用）。不分层就是把这些差异
   * 平均掉，平均出来的数字对任何具体场景都不适用。
   *
   * 由派活层写入（它才知道 target 形态），模型不需要关心。
   */
  shape: z.string().optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
})

export type Claim = z.infer<typeof claimSchema>

export const provenanceStateSchema = z.object({
  claims: z.array(claimSchema),
  confirmedCount: z.number(),
  refutedCount: z.number(),
})

export type ProvenanceState = z.infer<typeof provenanceStateSchema>

/** 升为「已验证事实」所需的独立路径数。 */
export const CONFIRM_THRESHOLD = 2

declare module '@deepseek-ai/dsh-session' {
  interface PluginRecordMap {
    'plugin:secops-claim': Claim
  }
}

export const CLAIM_PROJECTION_KEY = 'secopsProvenance'
export const CLAIM_RECORD_TYPE = 'plugin:secops-claim' as const

const EMPTY_STATE: ProvenanceState = { claims: [], confirmedCount: 0, refutedCount: 0 }

/** 断言 id 由内容派生：同一句话重复登记是幂等的。 */
export function claimIdFor(text: string): string {
  return `claim-${createHash('sha256').update(text.trim()).digest('hex').slice(0, 12)}`
}

function distinctPaths(evidence: readonly Evidence[]): number {
  return new Set(evidence.map((e) => e.pathKey)).size
}

/**
 * 由证据与显式状态推导 claim 的状态。
 *
 * 纯函数，便于单测：给定 evidence 与是否被显式证伪，返回状态。
 * 规则：
 *   - refuted 是一个单向闸门：一旦证伪，不会被新证据翻回来（要翻回来必须显式 reassert）
 *   - 独立路径数达到阈值 → confirmed
 *   - 有证据但不足阈值 → partial
 *   - 无证据 → hypothesis
 */
export function deriveStatus(
  evidence: readonly Evidence[],
  options: { refuted?: boolean; inference?: boolean; mode?: 'paths' | 'verified' | 'replay' } = {},
): ClaimStatus {
  if (options.refuted === true) return 'refuted'
  // 硬反驳优先：必须是 strong（系统读取的文件/记录），不接受模型自述。
  // 一票否决的理由见 role 注释——正向证据的数量不构成对硬事实的抵抗。
  // 只有 decisive 的反驳才翻转状态。advisory 留在证据里供复核，不动状态——
  // 见 evidenceSchema.refutation 的注释：把真漏洞反驳掉比报误报更糟。
  if (
    evidence.some(
      (e) =>
        e.role === 'refutation' &&
        e.relevance?.strength === 'strong' &&
        e.refutation?.kind === 'decisive',
    )
  ) {
    return 'refuted'
  }
  if (options.inference === true) return 'inference'
  // baseline 是对照，不构成「证明了几条独立路径」。把它算进去，
  // 两条正常请求就能把一条断言推到 confirmed——那正是要防的事。
  const proofOnly = evidence.filter(
    (e) => e.role !== 'baseline' && e.role !== 'control' && e.role !== 'refutation',
  )
  const count =
    options.mode === 'replay'
      ? new Set(
          proofOnly
            .filter((e) => e.relevance?.strength === 'strong' && e.replay?.verified === true)
            .map((e) => e.pathKey),
        ).size
      : options.mode === 'verified'
        ? new Set(proofOnly.filter((e) => e.relevance?.strength === 'strong').map((e) => e.pathKey)).size
        : distinctPaths(proofOnly)
  if (count >= CONFIRM_THRESHOLD) return 'confirmed'
  if (count >= 1) return 'partial'
  return 'hypothesis'
}

/** 新建一条断言。 */
export function newClaim(claim: string, options: { falsifier?: string; inference?: boolean } = {}): Claim {
  const now = Date.now()
  return {
    id: claimIdFor(claim),
    claim: claim.trim(),
    status: deriveStatus([], { inference: options.inference === true }),
    ...(options.falsifier === undefined ? {} : { falsifier: options.falsifier }),
    evidence: [],
    independentPaths: 0,
    createdAt: now,
    updatedAt: now,
  }
}

/** 追加证据并重算状态。同 ref 幂等。 */
export function withEvidence(
  claim: Claim,
  evidence: Evidence,
  options: { mode?: 'paths' | 'verified' } = {},
): Claim {
  // 去重要带上 role：同一份产物既是「正常请求」又是「越权证明」是不可能的，
  // 同一个 ref 用不同角色登记必须是两条记录。否则补 baseline 时会被判重复而静默丢弃，
  // 而「补了对照却被吞掉」比没补更糟——模型会以为已经补过了。
  const roleOf = (e: Evidence): string => e.role ?? 'proof'
  if (
    claim.evidence.some(
      (e) => e.ref === evidence.ref && e.pathKey === evidence.pathKey && roleOf(e) === roleOf(evidence),
    )
  ) {
    return claim
  }
  const next = [...claim.evidence, evidence]
  const refuted = claim.status === 'refuted'
  return {
    ...claim,
    evidence: next,
    independentPaths: distinctPaths(next),
    status: deriveStatus(next, { refuted, ...(options.mode === undefined ? {} : { mode: options.mode }) }),
    updatedAt: evidence.addedAt,
  }
}

/**
 * 已核实的证据才计入「强独立路径」。
 *
 * 这条是独立的计数口径：`independentPaths` 只数路径，
 * `verifiedPaths` 只数**通过相关性校验**的路径。升级为 confirmed 用后者。
 */
/**
 * 三条计数口径，逐级收紧：
 *   independentPaths —— 有几条不同来源的路径（最宽）
 *   strongPaths      —— 其中执行内容真的触及断言锚点的（相关性闸）
 *   replayPaths      —— 其中还能重跑复现的（重放闸，最硬）
 */
export function verifiedPaths(claim: Claim): number {
  return new Set(
    claim.evidence
      .filter((e) => e.role !== 'control' && e.relevance?.strength === 'strong')
      .map((e) => e.pathKey),
  ).size
}

/**
 * 按**实际工具**统计的独立路径数。
 *
 * 为什么要这个口径：`pathKey` 是调用方自报的，模型换个标签用同一工具跑两次
 * 就能声称两条独立路径。这里按可执行文件去重 —— 同一个工具最多贡献一条路径，
 * 想达标必须换工具，也就是换验证方法。
 *
 * 手工证据没有 source，退化为按 pathKey 计（它们本来也无法重放）。
 */
export function toolPaths(claim: Claim): number {
  const tools = new Set<string>()
  for (const e of claim.evidence) {
    // control 证据跑的是本地对照样本，不是目标。算进来就是凭空多一条路径。
    if (e.role === 'control') continue
    if (e.relevance?.strength !== 'strong' || e.replay?.verified !== true) continue
    tools.add(e.source?.argv[0] ?? `manual:${e.pathKey}`)
  }
  return tools.size
}

export function replayPaths(claim: Claim): number {
  return new Set(
    claim.evidence
      .filter((e) => e.role !== 'control' && e.relevance?.strength === 'strong' && e.replay?.verified === true)
      .map((e) => e.pathKey),
  ).size
}

/** 按角色分组的独立路径数。复核时先看这里：有没有对照，证明够不够。 */
export function pathRoles(claim: Claim): {
  readonly proof: number
  readonly baseline: number
  readonly control: number
} {
  const proof = new Set<string>()
  const baseline = new Set<string>()
  const control = new Set<string>()
  for (const e of claim.evidence) {
    if (e.role === 'control') {
      control.add(e.pathKey)
      continue
    }
    if (e.role === 'baseline') baseline.add(e.pathKey)
    else proof.add(e.pathKey)
  }
  return { proof: proof.size, baseline: baseline.size, control: control.size }
}

/**
 * 验证强度：这条断言被确认到了什么程度。
 *
 * 三档刻意分开，因为它们在真实评估里的可信度差一个量级：
 *
 *   none           —— 有证据，但没重跑过，也没对照。等于「工具这么说」。
 *   reproducible   —— 严格摘要重放通过：同一条命令再跑一次得到同样的输出。
 *                     证的是「可复现」，不是「真能打」——`echo "PUT /api/user 200"`
 *                     也能通过这一关。
 *   calibrated     —— 可复现 + **检测器**已用对照样本校准。
 *                     用于没有「目标正常态」可比的类（二进制加固 / TLS 配置）：
 *                     你没法让同一个二进制「加固着」当对照，只能证明工具在
 *                     已知样本上判得对。
 *   cross-checked  —— 可复现 + baseline 对照。这是唯一能说
 *                     「这个响应不正常」的档位：你知道正常情况下它返回什么。
 *
 * calibrated 与 cross-checked 互不替代、也不互相升级：
 *   - 有 baseline 无 control → cross-checked（目标对照过，工具坏没坏不知道）
 *   - 有 control 无 baseline → calibrated（工具校准过，目标没有可比正常态）
 *   - 两者都有 → cross-checked（更强的那一档，control 作为附加说明保留）
 * 不压成一个布尔，是因为「已验证」这个词在安全报告里必须可拆解。
 */
export type VerificationState = 'none' | 'reproducible' | 'calibrated' | 'cross-checked'

export function verificationOf(claim: Claim): VerificationState {
  const roles = pathRoles(claim)
  const strictReplay = claim.evidence.some(
    (e) => e.role !== 'baseline' && e.role !== 'control' && e.replay?.verified === true && e.replay?.matchKind === 'strict',
  )
  if (strictReplay && roles.baseline > 0) return 'cross-checked'
  if (strictReplay && roles.control > 0) return 'calibrated'
  if (strictReplay) return 'reproducible'
  return 'none'
}

/**
 * 哪些方向**必须**先过检测器对照才能声称验证到顶。
 *
 * 依据是「目标有没有可比正常态」：web 类可以用正常参数当 baseline；
 * 二进制加固 / TLS 配置 / 哈希识别这些没有，它们只能靠对照样本校准检测器。
 * 这些方向缺 control 就把断言顶到 cross-checked，等于用「工具输出」冒充
 * 「已对照」——正是要防的虚报。
 */
export const CONTROL_REQUIRED_CLASSES = ['binary', 'tls', 'crypto'] as const

export function needsControl(findingClass: string | undefined): boolean {
  return findingClass !== undefined && (CONTROL_REQUIRED_CLASSES as readonly string[]).includes(findingClass)
}

/** 有多少条证据是可重放的（带 source）。 */
export function replayableCount(claim: Claim): number {
  return claim.evidence.filter((e) => e.source !== undefined).length
}

/**
 * 显式证伪。
 *
 * blame 是「这条证据不可靠」的工具清单。它决定误报账记在谁头上：
 * 不传就只记 claim 被推翻，不归因到具体工具。
 */
export function withRefutation(
  claim: Claim,
  evidence: Evidence | undefined,
  at: number,
  blame?: readonly string[],
): Claim {
  const next = evidence === undefined ? claim.evidence : [...claim.evidence, evidence]
  // 归因是覆盖而不是累加：一条 claim 只被推翻一次，之后再 refute 都是修正。
  // 累加会让"记错了"变成"永远错下去"——误报账一旦写错就再也洗不掉，
  // 而这个账本的全部价值就在于它可信。
  const blame_ = blame === undefined || blame.length === 0 ? claim.blame : [...new Set(blame)]
  return {
    ...claim,
    evidence: next,
    independentPaths: distinctPaths(next),
    status: 'refuted',
    updatedAt: at,
    ...(blame_ === undefined ? {} : { blame: blame_ }),
  }
}

/** 是否已定论（confirmed 或 refuted）。已定论的路径不应被重复派发。 */
export function isSettled(claim: Claim): boolean {
  return claim.status === 'confirmed' || claim.status === 'refuted'
}

/** 写入一条 claim 快照到 session log。 */
export function recordClaim(session: Session, claim: Claim): number {
  return appendPluginRecord(session, CLAIM_RECORD_TYPE, claim)
}

/** projection 注册器的最小形状（避免直接依赖 ctx 类型）。 */
export interface ProjectionRegistryLike {
  register(definition: unknown): Promise<unknown>
  stateOf?(session: unknown, key: string): unknown
}

export async function registerProvenanceProjection(registry: ProjectionRegistryLike): Promise<void> {
  await registry.register({
    key: CLAIM_PROJECTION_KEY,
    stateVersion: 1,
    stateSchema: provenanceStateSchema,
    init: () => EMPTY_STATE,
    apply(state: ProvenanceState, event: SessionEvent): ProvenanceState {
      const rec = pluginRecordOf(event)
      if (rec === undefined || rec.type !== CLAIM_RECORD_TYPE) return state
      const claim = rec.data as Claim
      // 同一 claim 的后续快照覆盖前一条（last-wins），投影只保留当前状态。
      const rest = state.claims.filter((c) => c.id !== claim.id)
      const claims = [...rest, claim]
      return {
        claims,
        confirmedCount: claims.filter((c) => c.status === 'confirmed').length,
        refutedCount: claims.filter((c) => c.status === 'refuted').length,
      }
    },
  })
}

export function readProvenance(registry: ProjectionRegistryLike, session: unknown): ProvenanceState | undefined {
  if (registry.stateOf === undefined) return undefined
  return registry.stateOf(session, CLAIM_PROJECTION_KEY) as ProvenanceState | undefined
}
