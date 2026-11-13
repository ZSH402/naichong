/**
 * Provenance 的模型侧工具与内存状态容器。
 *
 * 状态容器与 session 解耦：有 session 时每次变更都 append 一条 plugin record
 * （供 projection 折叠、跨恢复保留）；没有 session 时退化为纯内存，便于测试。
 */

import fs from 'node:fs'
import path from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Session } from '@deepseek-ai/dsh-session'
import { checkEvidenceRelevance, type RelevanceVerdict } from './relevance.ts'
import { replayCommand, type ReplayOutcome } from './replay.ts'
import {
  CONFIRM_THRESHOLD,
  isSettled,
  newClaim,
  pathRoles,
  recordClaim,
  verificationOf,
  withEvidence,
  withRefutation,
  type Claim,
  type ClaimStatus,
  type Evidence,
} from './provenance.ts'

/** 单条证据的重放结果。 */
export interface VerifyEntry {
  readonly ref: string
  readonly pathKey: string
  readonly outcome: ReplayOutcome
  readonly verified: boolean
}

/** claim_verify 的结果。 */
export interface VerifyResult {
  readonly ok: boolean
  readonly checked: number
  readonly verified: number
  readonly results: readonly VerifyEntry[]
  readonly reason?: string
}

/** attach 的结果。失败时带判定依据，便于模型修正而不是盲试。 */
export type AttachResult =
  | { readonly ok: true; readonly claim: Claim; readonly rejected?: 'duplicate' }
  | { readonly ok: false; readonly reason: string; readonly verdict?: RelevanceVerdict }

/**
 * 认知进展事件。时间信用只认这些，不认模型自述。
 *
 * 为什么挂在这里而不是工具层：只有 ClaimStore 知道证据**通过没通过**锚点校验、
 * 独立路径有没有真的增加。工具层只看到模型提交了什么。
 */
export interface ClaimProgressEvent {
  readonly kind: 'hypothesis' | 'strong-evidence' | 'independent-path' | 'refutation'
  readonly claimId: string
  readonly detail: string
}

export class ClaimStore {
  private readonly claims = new Map<string, Claim>()
  private session: Session | undefined
  /** 严格模式：断言没有可核对锚点时直接拒绝。 */
  private readonly strictRelevance: boolean
  /** 跨会话快照文件（JSONL）。 */
  private readonly storePath: string | undefined
  /** 快照写入失败次数；>0 说明磁盘或权限有问题。 */
  private persistFailures = 0
  /**
   * 每次写入自增的版本号。
   *
   * 给下游那些「从 claims 现算」的账本（信誉分）一个廉价的失效判据：
   * 版本没变就不必重算。不像事件订阅那样需要注册/注销，也不会漏事件——
   * 漏一个事件只表现为「数字旧了一点」，而版本号只会滞后到下一次查询。
   */
  private revision = 0
  private lastPersistError: string | undefined

  private readonly onProgress: ((event: ClaimProgressEvent) => void) | undefined

  /**
   * 校准证据的准入判定。
   *
   * 由外部注入而不是在 ClaimStore 里直接 import 检测器账本：这个类不该知道
   * 检测器长什么样，它只需要一个「这条 calibration 能不能算数」的回答。
   * 不注入时 role=control 一律不算数——没有账本就没法核对，宁可让模型
   * 回去跑 detector_check，也不接受一条无法追溯来源的校准声明。
   */
  private readonly controlGate: ((ref: string) => { ok: true } | { ok: false; reason: string }) | undefined

  constructor(
    session?: Session,
    options: {
      strictRelevance?: boolean
      storePath?: string
      onProgress?: (event: ClaimProgressEvent) => void
      controlGate?: (ref: string) => { ok: true } | { ok: false; reason: string }
    } = {},
  ) {
    this.session = session
    this.strictRelevance = options.strictRelevance ?? true
    this.storePath = options.storePath
    this.onProgress = options.onProgress
    this.controlGate = options.controlGate
    if (this.storePath !== undefined) this.loadSnapshot()
  }

  /**
   * 从快照文件恢复。last-wins：同一 claim 的后续快照覆盖先前。
   * 半行（写入中途崩溃）直接跳过 —— append-only 的价值就在这里。
   */
  private loadSnapshot(): void {
    const file = this.storePath!
    if (!fs.existsSync(file)) return
    let text: string
    try {
      text = fs.readFileSync(file, 'utf8')
    } catch {
      return
    }
    for (const line of text.split('\n')) {
      const trimmed = line.trim()
      if (trimmed.length === 0) continue
      try {
        const claim = JSON.parse(trimmed) as Claim
        if (typeof claim?.id === 'string') this.claims.set(claim.id, claim)
      } catch {
        continue
      }
    }
  }

  /** 追加一条快照。失败只记录，不阻断判定流程。 */
  private persist(claim: Claim): void {
    if (this.storePath === undefined) return
    try {
      fs.mkdirSync(path.dirname(this.storePath), { recursive: true })
      fs.appendFileSync(this.storePath, `${JSON.stringify(claim)}\n`, 'utf8')
    } catch (error) {
      // 不阻断判定，但必须留痕：静默丢证据比直接报错更危险。
      this.persistFailures += 1
      this.lastPersistError = String(error)
    }
  }

  /** 绑定 session：之后的变更都会落 session log。 */
  bind(session: Session): void {
    this.session = session
  }

  /**
   * 首次工具调用时从 exec.agent.session 自动绑定。
   * 插件加载时还没有 session，硬绑定会在 apply 阶段拿不到东西。
   */
  ensureSession(exec: unknown): void {
    if (this.session !== undefined) return
    const agent = (exec as { agent?: { session?: Session } } | undefined)?.agent
    if (agent?.session !== undefined) this.session = agent.session
  }

  private commit(claim: Claim): Claim {
    this.revision += 1
    this.claims.set(claim.id, claim)
    this.persist(claim)
    if (this.session !== undefined) {
      try {
        recordClaim(this.session, claim)
      } catch {
        // 记录失败不阻断判定流程 —— 内存状态仍然有效。
      }
    }
    return claim
  }

  assert(claimText: string, options: { falsifier?: string; inference?: boolean } = {}): Claim {
    const existing = this.claims.get(newClaim(claimText).id)
    if (existing !== undefined) return existing
    const claim = this.commit(newClaim(claimText, options))
    // 只有带可证伪条件的断言才算进展。没有 falsifier 的断言是一句话，不是一个假设。
    if (options.falsifier !== undefined && options.falsifier.trim() !== '') {
      this.emit({ kind: 'hypothesis', claimId: claim.id, detail: claimText.slice(0, 120) })
    }
    return claim
  }

  private emit(event: ClaimProgressEvent): void {
    try {
      this.onProgress?.(event)
    } catch {
      /* 记账失败不影响证据链本身 */
    }
  }

  /**
   * 追加证据。**先过相关性校验**：证据的实际执行内容必须触及断言的锚点。
   *
   * 这是为了堵住「拿无关任务产物充当证据」——端到端验证里模型用
   * `node -e "console.log(7)"` 给 `PUT /api/user` 越权断言作证，
   * 旧实现照单全收并把它计为一条独立路径。
   */
  attach(
    claimId: string,
    evidence: Omit<Evidence, 'addedAt' | 'relevance' | 'observed' | 'replay'> & {
      executed?: string
      artifact?: string
    },
  ): AttachResult {
    const prev = this.claims.get(claimId)
    if (prev === undefined) return { ok: false, reason: `unknown claim: ${claimId}` }

    const { executed: _e, artifact: _a, ...rest } = evidence
    void _e
    void _a

    // 校准证据跑的是本地对照样本（例如 /usr/bin/ls），它**不可能**触及目标锚点。
    // 对它做相关性检查必然判 none，然后被当成「不相关证据」拒收——这不是质量问题，
    // 是检查对象不同：它证明的是「尺子准」，不是「目标有问题」。
    // 但也不能因此放行任何东西：它单独不能确认任何断言（deriveStatus 排除 control），
    // 只在 verificationOf 里和一条可复现的 proof 合并成 calibrated。
    let strength: 'strong' | 'weak' = 'weak'
    let matched: string[] = []
    if (evidence.role === 'control') {
      // 校准证据的唯一合法来源是 detector_check。手写的 control ref 无法核对，
      // 而且它一旦被接受就能把任何一条断言顶到 calibrated——那等于开后门。
      const gate = this.controlGate
      const verdict = gate === undefined
        ? { ok: false as const, reason: 'role=control 需要先跑 detector_check 建立校准账本' }
        : gate(evidence.ref)
      if (!verdict.ok) return { ok: false, reason: verdict.reason }
    } else {
      const verdict = checkEvidenceRelevance(
        {
          claim: prev.claim,
          ...(evidence.executed === undefined ? {} : { executed: evidence.executed }),
          ...(evidence.artifact === undefined ? {} : { artifact: evidence.artifact }),
          ref: evidence.ref,
        },
        { strict: this.strictRelevance },
      )
      if (!verdict.ok) {
        return { ok: false, reason: verdict.reason ?? 'evidence is not relevant to the claim', verdict }
      }
      // verdict.ok 为真时 strength 必为 strong|weak（none 一定伴随 ok=false）。
      strength = verdict.strength === 'none' ? 'weak' : verdict.strength
      matched = verdict.matched.map((a) => `${a.kind}:${a.value}`)
    }
    const next = withEvidence(
      prev,
      {
        ...rest,
        relevance: { strength, matched },
        addedAt: Date.now(),
      },
      { mode: 'verified' },
    )
    if (next === prev) return { ok: true, claim: prev, rejected: 'duplicate' }
    const committed = this.commit(next)
    if (strength === 'strong') {
      this.emit({ kind: 'strong-evidence', claimId, detail: evidence.ref })
    }
    if (committed.independentPaths > prev.independentPaths) {
      this.emit({
        kind: 'independent-path',
        claimId,
        detail: `${String(prev.independentPaths)} → ${String(committed.independentPaths)} path(s) via ${evidence.pathKey}`,
      })
    }
    return { ok: true, claim: committed }
  }

  /**
   * 对 claim 里所有带来源的证据执行重放，回写结果并重算状态。
   *
   * 这是「证据自己证明自己」的执行体：不接受无法复现的证据作为强证据。
   * 重放会真实执行命令 —— 调用方要意识到这是有副作用的操作。
   */
  async verify(claimId: string): Promise<VerifyResult> {
    const claim = this.claims.get(claimId)
    if (claim === undefined) return { ok: false, checked: 0, verified: 0, results: [], reason: `unknown claim: ${claimId}` }

    const targets = claim.evidence.filter((e) => e.source !== undefined)
    if (targets.length === 0) {
      return { ok: false, checked: 0, verified: 0, results: [], reason: 'no replayable evidence (all entries lack a worker source)' }
    }

    const results: VerifyEntry[] = []
    let next: Claim = claim
    for (const target of targets) {
      const source = target.source!
      const outcome = await replayCommand({
        argv: source.argv,
        cwd: source.cwd,
        ...(target.baselineDigest === undefined ? {} : { baselineDigest: target.baselineDigest }),
        ...(target.baselineStrictDigest === undefined
          ? {}
          : { baselineStrictDigest: target.baselineStrictDigest }),
      })
      // 只有严格一致（数值也相同）才算复现成功。
      // 结构一致但数值不同，说明产物实质变了 —— 那正是重放要抓住的东西。
      const verified = outcome.ran && outcome.exitCode === 0 && outcome.matchKind === 'strict'
      results.push({ ref: target.ref, pathKey: target.pathKey, outcome, verified })

      // 逐条回写：一条失败不影响其它条的结果落盘。
      const evidence = next.evidence.map((e) =>
        e.ref === target.ref && e.pathKey === target.pathKey
          ? {
              ...e,
              replay: {
                verified,
                at: Date.now(),
                exitCode: outcome.exitCode,
                digest: outcome.digest,
                matchKind: outcome.matchKind,
                ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
              },
            }
          : e,
      )
      // 用「不同工具数」而不是「不同 pathKey 数」判定 confirmed：
      // 同一工具重复跑不构成独立复现。
      const toolCount = new Set(
        evidence
          .filter((e) => e.relevance?.strength === 'strong' && e.replay?.verified === true)
          .map((e) => e.source?.argv[0] ?? `manual:${e.pathKey}`),
      ).size
      next = {
        ...next,
        evidence,
        independentPaths: new Set(evidence.map((e) => e.pathKey)).size,
        status: toolCount >= CONFIRM_THRESHOLD ? 'confirmed' : toolCount >= 1 ? 'partial' : next.status,
        updatedAt: Date.now(),
      }
    }

    this.commit(next)
    const verifiedCount = results.filter((r) => r.verified).length
    return { ok: verifiedCount > 0, checked: results.length, verified: verifiedCount, results }
  }

  /** 当前版本。只增不减，进程内唯一。 */
  get version(): number {
    return this.revision
  }

  /**
   * 记下这条断言是在哪种目标形态下产生的。
   *
   * 只写第一次：一条断言可能被跨形态地反复派活，但它的结论最初来自哪个形态
   * 是固定的事实。后写的值会把这条事实改掉，让信誉分层失去意义。
   * 形态未知（undefined）时什么都不做——不写一个假值。
   */
  setShape(claimId: string, shape: string | undefined): Claim | undefined {
    if (shape === undefined || shape === '') return this.claims.get(claimId)
    const prev = this.claims.get(claimId)
    if (prev === undefined || prev.shape !== undefined) return prev
    return this.commit({ ...prev, shape, updatedAt: prev.updatedAt })
  }

  refute(claimId: string, evidence?: Omit<Evidence, 'addedAt'>, blame?: readonly string[]): Claim | undefined {
    const prev = this.claims.get(claimId)
    if (prev === undefined) return undefined
    if (prev.status !== 'refuted') {
      this.emit({ kind: 'refutation', claimId, detail: prev.claim.slice(0, 120) })
    }
    return this.commit(
      withRefutation(
        prev,
        evidence === undefined ? undefined : { ...evidence, addedAt: Date.now() },
        Date.now(),
        blame,
      ),
    )
  }

  /** 把资产 id 关联到 claim（去重追加）。 */
  linkAssets(claimId: string, assetIds: readonly string[]): void {
    const prev = this.claims.get(claimId)
    if (prev === undefined || assetIds.length === 0) return
    const merged = [...new Set([...(prev.assetIds ?? []), ...assetIds])]
    this.commit({ ...prev, assetIds: merged, updatedAt: Date.now() })
  }

  get(claimId: string): Claim | undefined {
    return this.claims.get(claimId)
  }

  query(filter: { status?: ClaimStatus; settledOnly?: boolean } = {}): Claim[] {
    let all = [...this.claims.values()]
    if (filter.status !== undefined) all = all.filter((c) => c.status === filter.status)
    if (filter.settledOnly === true) all = all.filter(isSettled)
    return all.sort((a, b) => a.createdAt - b.createdAt)
  }

  /** 快照写入诊断：失败次数与最近一次错误。 */
  persistStatus(): { failures: number; lastError?: string } {
    return {
      failures: this.persistFailures,
      ...(this.lastPersistError === undefined ? {} : { lastError: this.lastPersistError }),
    }
  }

  /** 已定论（confirmed/refuted）的 id 集合，供调度器跳过重复派发。 */
  settledIds(): string[] {
    return [...this.claims.values()].filter(isSettled).map((c) => c.id)
  }
}

const EVIDENCE_SCHEMA = {
  type: 'object',
  properties: {
    ref: { type: 'string' },
    pathKey: { type: 'string' },
    note: { type: 'string' },
    tool: { type: 'string', description: 'Which executable produced this evidence (basename).' },
    role: { type: 'string', description: 'proof | baseline (absent means proof).' },
    taskId: { type: 'string' },
  },
  required: ['ref', 'pathKey'],
} as const

const CLAIM_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    claim: { type: 'string' },
    status: { type: 'string' },
    independentPaths: { type: 'number' },
    falsifier: { type: 'string' },
    evidenceCount: { type: 'number' },
    evidence: { type: 'array', items: EVIDENCE_SCHEMA },
    hint: { type: 'string', description: 'What is still weak about this claim, e.g. a missing baseline.' },
    assetIds: { type: 'array', items: { type: 'string' }, description: 'Assets this claim concerns.' },
    paths: {
      type: 'object',
      properties: { proof: { type: 'number' }, baseline: { type: 'number' } },
      required: ['proof', 'baseline'],
      description: 'Independent paths by role. Only proof paths count toward confirmation.',
    },
    blame: {
      type: 'array',
      items: { type: 'string' },
      description: 'Tools whose evidence was refuted. Empty means the refutation was not attributed.',
    },
  },
  required: ['id', 'claim', 'status', 'independentPaths', 'evidenceCount', 'evidence'],
} as const

/**
 * 模型可见的 claim 视图。
 *
 * 必须带 evidence 明细：端到端验证里模型因为没有这个字段而无法核实
 * "证据数量"，只能靠 independentPaths 反推。审计类接口不能只说结论。
 */
function project(claim: Claim): Record<string, unknown> {
  return {
    id: claim.id,
    claim: claim.claim,
    status: claim.status,
    independentPaths: claim.independentPaths,
    evidenceCount: claim.evidence.length,
    evidence: claim.evidence.map((e) => ({
      ref: e.ref,
      pathKey: e.pathKey,
      ...(e.note === undefined ? {} : { note: e.note }),
      // 来源必须可见：不知道证据是哪个工具产的，就没法判断该不该信它，
      // 也没法在推翻时给出 blame。
      ...(e.source === undefined ? {} : { tool: e.source.argv[0]?.split('/').pop() ?? e.source.argv[0], taskId: e.source.taskId }),
      ...(e.role === undefined ? {} : { role: e.role }),
    })),
    ...(claim.falsifier === undefined ? {} : { falsifier: claim.falsifier }),
    ...(claim.blame === undefined ? {} : { blame: claim.blame }),
    paths: pathRoles(claim),
    // 验证强度必须回到模型眼前。只在 submit_answer 时才被查，等于让它蒙着眼睛
    // 走到最后一步才知道自己只有 "reproducible"。
    verification: verificationOf(claim),
    ...(claim.assetIds === undefined ? {} : { assetIds: claim.assetIds }),
    // 没有对照的证明，复核者无法区分「越权读到了」和「接口本来就这么返回」。
    // 不强制（不是所有漏洞都有可对照的正常情况），但必须让人和模型都看得见。
    ...(() => {
      const r = pathRoles(claim)
      // 返回空对象而不是 { hint: undefined }：undefined 不是合法 JSON 值，
      // 工具输出会整体序列化失败——恰好是「证据最齐全」的那些 claim 最容易被它打挂。
      if (r.proof === 0 || r.baseline > 0) return {}
      if (r.control > 0) {
        return {
          hint:
            `这条断言有 ${String(r.proof)} 条证明路径 + 检测器校准，但没有**目标**的 baseline 对照 ` +
            `（verification=calibrated）。工具可信不等于目标行为已对照：` +
            `如果这个类确实没有「正常态」可比（二进制加固、TLS 配置），calibrated 就是上限，` +
            `报告里要写明这一点；如果可比（表单类漏洞几乎总是可比），补一条正常输入的 role=baseline。`,
        }
      }
      return {
        hint:
          `这条断言有 ${String(r.proof)} 条证明路径，但没有 baseline 对照。` +
          `补一条「同一请求用正常参数再打一次」的证据（role=baseline）：` +
          `没有对照，复核者无法判断这是真漏洞还是接口本来就这样返回。` +
          `若该类没有可比的正常态（缺加固、TLS 弱配置），先跑 detector_check 再附 role=control。`,
      }
    })(),
  }
}

export function provenanceTools(store: ClaimStore): ToolDefinition[] {
  const assertTool: ToolDefinition = {
    name: 'claim_assert',
    description:
      'Register a falsifiable claim you intend to prove or disprove. Must be a specific statement, not a class name. ' +
      'Idempotent by claim text. Status starts at "hypothesis".\n\n' +
      'Use this beyond scanning: any investigation where you form a belief and then test it belongs here — ' +
      'reverse engineering ("the 256 bits at the tail are the flag in order"), crypto ("the cipher is ECB"), ' +
      'forensics ("the payload starts at offset 0x2000"). Writing the belief down with its falsifier keeps you ' +
      'from drifting into variations of the same guess, and claim_evidence gives you a place to park what you ' +
      'actually observed. If you have been running variations of one hypothesis for a while without narrowing it, ' +
      'that is the signal to record it here and go after the falsifier directly.',
    parameters: {
      type: 'object',
      properties: {
        claim: { type: 'string', description: 'The falsifiable statement.' },
        falsifier: { type: 'string', description: 'What observation would prove this claim false.' },
        inference: { type: 'boolean', description: 'Mark as Agent inference instead of an observed hypothesis.' },
      },
      required: ['claim'],
    },
    output: {
      schema: CLAIM_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v) }],
    },
    execute: async (args: unknown, exec: unknown) => {
      const a = args as { claim: string; falsifier?: string; inference?: boolean }
      store.ensureSession(exec)
      return project(
        store.assert(a.claim, {
          ...(a.falsifier === undefined ? {} : { falsifier: a.falsifier }),
          ...(a.inference === undefined ? {} : { inference: a.inference }),
        }),
      )
    },
  }

  const evidenceTool: ToolDefinition = {
    name: 'claim_evidence',
    description:
      `Attach evidence to a claim. The evidence must actually concern the claim: the executed command or request ` +
      `has to mention one of the claim's anchors (path / HTTP method / param / host / status). ` +
      `Independence is declared by path_key — evidences sharing one path_key count as a single path. ` +
      `A claim reaches "confirmed" at ${CONFIRM_THRESHOLD} verified independent paths.`,
    parameters: {
      type: 'object',
      properties: {
        claim_id: { type: 'string' },
        ref: { type: 'string', description: 'Evidence reference: file path, evidence id, request hash.' },
        path_key: { type: 'string', description: 'Independence key, e.g. "http:differential", "tool:recompute", "role:other-user".' },
        executed: {
          type: 'string',
          description:
            'The command or request line that produced this evidence, e.g. "curl -X PUT https://t/api/user -d role=admin". ' +
            'It must mention one of the claim anchors; a self-written narration of what you think you observed is not accepted.',
        },
        note: { type: 'string' },
        asset_ids: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Assets this evidence concerns, e.g. ["10.0.0.5:445"]. Links the claim into the asset store so ' +
            '"what did we establish about this service" is answerable later. Use asset_list to see known ids.',
        },
        role: {
          type: 'string',
          description:
            'proof (default) — shows the problem exists. baseline — the normal case on the TARGET it is compared ' +
            'against. control — a calibration run: the same detection command against a sample whose answer is ' +
            'already known, proving the detector itself works. Use control for classes with no normal state to ' +
            'compare (binary hardening, TLS config): run detector_check, save the output, attach it as role=control. ' +
            'Only proof paths count toward confirmation.',
        },
      },
      required: ['claim_id', 'ref', 'path_key'],
    },
    output: {
      schema: CLAIM_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v) }],
    },
    execute: async (args: unknown, exec: unknown) => {
      const a = args as {
        claim_id: string
        ref: string
        path_key: string
        note?: string
        executed?: string
        role?: string
        asset_ids?: string[]
      }
      store.ensureSession(exec)
      const role = a.role === 'baseline' ? 'baseline' : a.role === 'control' ? 'control' : a.role === 'proof' ? 'proof' : undefined
      const result = store.attach(a.claim_id, {
        ref: a.ref,
        pathKey: a.path_key,
        ...(a.note === undefined ? {} : { note: a.note }),
        ...(a.executed === undefined ? {} : { executed: a.executed }),
        ...(role === undefined ? {} : { role }),
      })
      if (!result.ok) return { error: result.reason }
      // 把资产关联写回 claim：反过来按资产查证据链才有落脚点。
      const assetIds = Array.isArray(a.asset_ids) ? a.asset_ids.filter((x) => typeof x === 'string' && x !== '') : []
      if (assetIds.length > 0) store.linkAssets(a.claim_id, assetIds)
      return project(store.get(a.claim_id) ?? result.claim)
    },
  }

  const refuteTool: ToolDefinition = {
    name: 'claim_refute',
    description:
      'Mark a claim refuted. A refuted claim is terminal: it will not be promoted back by later evidence, ' +
      'and the planner should not dispatch more work against it.',
    parameters: {
      type: 'object',
      properties: {
        claim_id: { type: 'string' },
        ref: { type: 'string', description: 'Evidence that refutes it.' },
        path_key: { type: 'string' },
        note: { type: 'string' },
        blame_agent: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Which tool(s) produced the bad evidence. Omit when unsure — an unattributed refutation still counts as ' +
            'a refutation but does not damage any agent\'s precision score. Do not list an agent whose evidence still ' +
            'stands, and do not blame a tool for a hypothesis you invented: if the tool ran clean and found nothing, ' +
            'the claim was wrong, not the tool. Calling claim_refute again on the same claim REPLACES the blame, ' +
            'so a mistaken attribution can be corrected.',
        },
      },
      required: ['claim_id'],
    },
    output: {
      schema: CLAIM_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v) }],
    },
    execute: async (args: unknown, exec: unknown) => {
      const a = args as { claim_id: string; ref?: string; path_key?: string; note?: string; blame_agent?: string[] }
      store.ensureSession(exec)
      const evidence =
        a.ref === undefined
          ? undefined
          : { ref: a.ref, pathKey: a.path_key ?? 'refutation', ...(a.note === undefined ? {} : { note: a.note }) }
      const blame = Array.isArray(a.blame_agent) ? a.blame_agent.filter((x) => typeof x === 'string' && x.length > 0) : undefined
      const next = store.refute(a.claim_id, evidence, blame)
      return next === undefined ? { error: `unknown claim: ${a.claim_id}` } : project(next)
    },
  }

  const queryTool: ToolDefinition = {
    name: 'claim_query',
    description:
      'Read claims and their evidence. Use settled_only to list what must not be re-attempted (confirmed or refuted). ' +
      'When you feel stuck, query the open claims: the list of what you believed but never tested is usually the ' +
      'fastest way to see where the investigation actually stopped.',
    parameters: {
      type: 'object',
      properties: {
        status: { type: 'string', description: 'Filter by status.' },
        settled_only: { type: 'boolean', description: 'Only confirmed or refuted claims.' },
      },
    },
    output: {
      schema: {
        type: 'object',
        properties: { claims: { type: 'array', items: CLAIM_SCHEMA } },
        required: ['claims'],
      } as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown, exec: unknown) => {
      const a = (args ?? {}) as { status?: ClaimStatus; settled_only?: boolean }
      store.ensureSession(exec)
      const claims = store.query({
        ...(a.status === undefined ? {} : { status: a.status }),
        ...(a.settled_only === undefined ? {} : { settledOnly: a.settled_only }),
      })
      return { claims: claims.map(project) }
    },
  }

  const verifyTool: ToolDefinition = {
    name: 'claim_verify',
    description:
      'Replay every replayable evidence of a claim and store the outcome. A claim can only reach "confirmed" ' +
      'when at least ' + CONFIRM_THRESHOLD + ' independent paths are strong AND at least one replay reproduced ' +
      'the recorded artifact. This actually executes the recorded commands — expect real network traffic.',
    parameters: {
      type: 'object',
      properties: {
        claim_id: { type: 'string' },
      },
      required: ['claim_id'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          checked: { type: 'number' },
          verified: { type: 'number' },
          status: { type: 'string' },
          results: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                ref: { type: 'string' },
                pathKey: { type: 'string' },
                verified: { type: 'boolean' },
                exitCode: { type: 'number' },
                matchesBaseline: { type: 'boolean' },
                reason: { type: 'string' },
              },
              required: ['ref', 'pathKey', 'verified'],
            },
          },
          reason: { type: 'string' },
        },
        required: ['ok', 'checked', 'verified'],
      } as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown, exec: unknown) => {
      const a = args as { claim_id: string }
      store.ensureSession(exec)
      const result = await store.verify(a.claim_id)
      const claim = store.get(a.claim_id)
      return {
        ok: result.ok,
        checked: result.checked,
        verified: result.verified,
        ...(claim === undefined ? {} : { status: claim.status }),
        results: result.results.map((r) => ({
          ref: r.ref,
          pathKey: r.pathKey,
          verified: r.verified,
          ...(r.outcome.exitCode === null ? {} : { exitCode: r.outcome.exitCode }),
          matchesBaseline: r.outcome.matchesBaseline,
          ...(r.outcome.reason === undefined ? {} : { reason: r.outcome.reason }),
        })),
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      }
    },
  }

  return [assertTool, evidenceTool, verifyTool, refuteTool, queryTool]
}

export function installProvenanceTools(ctx: Context, store: ClaimStore): void {
  for (const tool of provenanceTools(store)) ctx.tools.register(tool)
}
