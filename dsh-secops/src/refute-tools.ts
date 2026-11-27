/**
 * 白盒反驳工具：把「代码事实」变成能翻转断言状态的证据。
 *
 * 为什么做成工具而不是后台自动跑：
 *
 *   反驳的输入是断言里的锚点，而锚点是否可搜、仓库根在哪、这次要不要真的判死，
 *   都是现场判断。自动跑会把"仓库没同步"、"路径写错"这类环境问题变成静默误杀。
 *
 * 证据怎么进库（这一步是这个文件的关键）：
 *
 *   检查结果先落成文件，再以 `artifact + artifactTrusted` 的形式 attach。
 *   绕不过去——`relevance` 的 strong 只认系统读的文件，这样一条反驳才能
 *   进入 `deriveStatus` 的判死分支；反过来，模型自己写一段"我认为这不可达"
 *   永远拿不到 strong，也就永远杀不掉任何东西。
 *
 *   这不是形式主义：Refute-or-Promote 的实证里，10 个专职审查员全票认可的
 *   一个漏洞，最终只被一条实证测试击毙。**能被复核的事实才有否决权。**
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { ClaimStore } from './provenance-tools.ts'
import { extractAnchors } from './relevance.ts'
import { refutePath, refuteSymbol } from './refute/facts.ts'
import type { RefuteFinding, RefuteReport } from './refute/facts.ts'

const REPORT_SCHEMA = {
  type: 'object',
  properties: {
    claim_id: { type: 'string' },
    status: { type: 'string' },
    verdict: { type: 'string' },
    decisive: { type: 'number' },
    advisory: { type: 'number' },
    evidence_ref: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          anchor: { type: 'string' },
          kind: { type: 'string' },
          check: { type: 'string' },
          location: { type: 'string' },
          detail: { type: 'string' },
        },
        required: ['anchor', 'kind', 'check'],
      },
    },
    degraded: { type: 'string' },
  },
  required: ['claim_id', 'status', 'verdict', 'decisive', 'advisory', 'findings'],
} as const

export interface RefuteToolsOptions {
  /** 反驳报告落盘目录。默认走临时目录下按 claim 分文件。 */
  readonly outDir?: string
}

/**
 * 从断言里选可搜的目标。
 *
 * 只挑两类，且**参数名不参与反驳**——这条是被一次误杀逼出来的：
 *
 *   断言 "POST /api/user/export 未校验租户归属" 里的 `user` 曾被当成符号去做
 *   "有没有调用方"的检查，结果仓库里当然没有 `user(` 这样的调用点，于是
 *   一条真漏洞被判成死代码直接 refuted。
 *
 * 教训：**参数名不是符号**。`user`、`role` 这类词在源码里出现的方式和函数名
 * 完全不同（它们作为字段名、路由片段、字符串字面量出现），拿函数调用的口径
 * 去搜必然搜不到，"搜不到"就更不能当成"不存在"。
 *
 * 所以现在的规则是：
 *   path  —— 路由/文件路径，用 refutePath（找不到可以判死）
 *   call  —— 断言里明确写成 `name(` 的调用，才用 refuteSymbol
 *   其余  —— 不搜，不反驳
 */
function pickTargets(claimText: string): { value: string; kind: 'path' | 'call' }[] {
  const out: { value: string; kind: 'path' | 'call' }[] = []
  const seen = new Set<string>()

  for (const a of extractAnchors(claimText)) {
    if (a.kind !== 'path') continue
    if (a.value.length < 4) continue
    const key = `path:${a.value}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ value: a.value, kind: 'path' })
  }

  // 只认断言里显式写成调用形式的标识符：`loadAll(...)`
  for (const m of claimText.matchAll(/\b([a-z_][a-zA-Z0-9_]{3,})\s*\(/g)) {
    const name = m[1]!
    const key = `call:${name}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ value: name, kind: 'call' })
  }
  return out
}

export function refuteTools(store: ClaimStore, opts: RefuteToolsOptions = {}): ToolDefinition[] {
  const outDir = opts.outDir ?? path.join(os.tmpdir(), 'secops-refute')

  const refuteTool: ToolDefinition = {
    name: 'refute_by_code',
    description:
      'Try to PROVE A CLAIM WRONG using deterministic code facts, and record the result as refutation evidence. ' +
      'It searches the repository for the anchors in the claim (route paths, parameter names) and reports: ' +
      '(a) anchor-absent — the endpoint the claim talks about does not exist anywhere in this repo; ' +
      '(b) route-unregistered — the string exists but no handler registers it; ' +
      '(c) guard-found — a registration site has an auth/tenant check nearby. ' +
      'Only (a) is decisive and flips the claim to refuted; (b) and (c) are recorded as advisory leads and do ' +
      'NOT change the status, because killing a real finding is worse than reporting a false one. ' +
      'Use it after a claim exists, and pass the repository root that the claim is about.',
    parameters: {
      type: 'object',
      properties: {
        claim_id: { type: 'string', description: 'Claim to attack.' },
        repo: { type: 'string', description: 'Repository root to search (source tree of the target).' },
        dry_run: { type: 'boolean', description: 'Only report; do not attach the evidence.' },
      },
      required: ['claim_id', 'repo'],
    },
    output: {
      schema: REPORT_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as { claim_id?: string; repo?: string; dry_run?: boolean }
      const claimId = a.claim_id ?? ''
      const repo = a.repo ?? ''
      const claim = store.get(claimId)
      if (claim === undefined) {
        return {
          claim_id: claimId, status: 'unknown', verdict: 'unknown claim', decisive: 0, advisory: 0,
          evidence_ref: '', findings: [],
        }
      }
      if (repo === '' || !fs.existsSync(repo)) {
        return {
          claim_id: claimId, status: claim.status, verdict: `repo not found: ${repo}`,
          decisive: 0, advisory: 0, evidence_ref: '', findings: [],
        }
      }

      const anchors = pickTargets(claim.claim)
      if (anchors.length === 0) {
        return {
          claim_id: claimId, status: claim.status,
          verdict: 'claim has no searchable anchors (route path or parameter name); rewrite it as a specific statement',
          decisive: 0, advisory: 0, evidence_ref: '', findings: [],
        }
      }

      const reports: RefuteReport[] = []
      for (const an of anchors) {
        reports.push(
          an.kind === 'path'
            ? await refutePath(repo, an.value)
            : await refuteSymbol(repo, an.value),
        )
      }

      const flat: (RefuteFinding & { anchor: string })[] = []
      for (const r of reports) {
        for (const f of r.findings) flat.push({ ...f, anchor: r.anchor })
      }
      const decisive = flat.filter((f) => f.kind === 'decisive').length
      const advisory = flat.filter((f) => f.kind === 'advisory').length
      const degraded = reports.map((r) => r.degraded).find((d) => d !== null) ?? undefined

      const verdict =
        decisive > 0
          ? 'refuted by decisive code fact'
          : advisory > 0
            ? 'no decisive fact; advisory leads recorded (status unchanged)'
            : 'no contradiction found in the repository'

      let evidenceRef = ''
      if (a.dry_run !== true && flat.length > 0) {
        // 结果落盘：人能打开这份文件复核反驳依据
        fs.mkdirSync(outDir, { recursive: true })
        const file = path.join(outDir, `${claimId}-${String(Date.now())}.json`)
        fs.writeFileSync(
          file,
          JSON.stringify({ claim: claim.claim, repo, anchors, searches: reports.reduce((s, r) => s + r.searches, 0), degraded, findings: flat }, null, 2),
          'utf8',
        )
        const artifact = fs.readFileSync(file, 'utf8')
        const top = flat.find((f) => f.kind === 'decisive') ?? flat[0]!
        const res = store.attach(claimId, {
          ref: `refute:${top.check}`,
          pathKey: `refute:${repo}`,
          artifact,
          artifactTrusted: true,
          role: 'refutation',
          refutation: {
            kind: top.kind,
            check: top.check,
            ...(top.location === undefined ? {} : { location: top.location }),
            detail: top.detail.slice(0, 300),
          },
          ...(degraded === undefined ? {} : { note: degraded }),
        })
        if (res.ok) evidenceRef = file
      }

      const after = store.get(claimId)
      return {
        claim_id: claimId,
        status: after?.status ?? claim.status,
        verdict,
        decisive,
        advisory,
        evidence_ref: evidenceRef,
        findings: flat.map((f) => ({
          anchor: f.anchor,
          kind: f.kind,
          check: f.check,
          ...(f.location === undefined ? {} : { location: f.location }),
          detail: f.detail,
        })),
        ...(degraded === undefined ? {} : { degraded }),
      }
    },
  }

  return [refuteTool]
}
