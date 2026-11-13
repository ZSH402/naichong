/**
 * 误报账本验收。
 *
 * 这个数字最容易被算成好看的假象，所以每条断言都针对一个具体的失真方式：
 *   - 按执行次数算而不是按 claim 算 → 同一个工具跑三次变成三次判断
 *   - 没归因的推翻也记黑账 → 一条 claim 里正确的工具跟着背锅
 *   - 把未定论的算进分母 → 误报率被稀释
 *   - 样本不足就给比率 → 三条错一条变成 33%
 */

import { analyzePrecision, agentsOfClaim, precisionActions, MIN_SAMPLE } from '../dist/council/precision.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const ev = (tool, ref = `r-${tool}`) => ({
  ref,
  pathKey: `key-${tool}`,
  source: { kind: 'worker', taskId: `t-${tool}`, argv: [`/usr/bin/${tool}`, '--scan', 'target'], cwd: '/tmp' },
  addedAt: 1,
})

const claim = (id, status, evidence, blame) => ({
  id,
  claim: `claim ${id}`,
  status,
  evidence,
  independentPaths: new Set(evidence.map((e) => e.pathKey)).size,
  ...(blame === undefined ? {} : { blame }),
  createdAt: 1,
  updatedAt: 2,
})

// ── 1. 从证据里认工具
{
  const c = claim('c1', 'hypothesis', [ev('nuclei'), ev('nuclei', 'r2'), ev('semgrep')])
  const agents = agentsOfClaim(c)
  check('distinct tools are deduped', agents.length === 2, agents)
  check('tool name is the basename', agents.includes('nuclei') && agents.includes('semgrep'), agents)

  const manual = claim('c2', 'hypothesis', [{ ref: 'x', pathKey: 'k', addedAt: 1 }])
  check('manual evidence has no tool', agentsOfClaim(manual).length === 0)
}

// ── 2. 按 claim 计数，不按执行次数
{
  // 同一条 claim 里 nuclei 出现两次：只算一次判断
  const report = analyzePrecision([claim('c1', 'confirmed', [ev('nuclei'), ev('nuclei', 'r-2')])])
  const n = report.agents.find((a) => a.agent === 'nuclei')
  check('one claim counts once even with two evidence rows', n?.reported === 1, n)
  check('confirmed counted', n?.confirmed === 1, n)
}

// ── 3. 归因才记黑账
{
  const attributed = analyzePrecision([
    claim('c1', 'refuted', [ev('nuclei'), ev('semgrep')], ['nuclei']),
  ])
  const n = attributed.agents.find((a) => a.agent === 'nuclei')
  const s = attributed.agents.find((a) => a.agent === 'semgrep')
  check('blamed agent gets the refutation', n?.refuted === 1, n)
  check('unblamed agent does not', s?.refuted === 0, s)
  check('unblamed agent counts as still open', s?.open === 1, s)
  check('nothing left unattributed here', attributed.unattributedRefutations === 0)

  const unattributed = analyzePrecision([claim('c1', 'refuted', [ev('nuclei')])])
  const n2 = unattributed.agents.find((a) => a.agent === 'nuclei')
  check('refutation without blame damages nobody', n2?.refuted === 0, n2)
  check('but it is reported as invisible', unattributed.unattributedRefutations === 1, unattributed.unattributedRefutations)
}

// ── 4. 分母是已定论，不含未定论
{
  const claims = [
    claim('c1', 'confirmed', [ev('nuclei')]),
    claim('c2', 'hypothesis', [ev('nuclei')]),
    claim('c3', 'partial', [ev('nuclei')]),
  ]
  const r = analyzePrecision(claims)
  const n = r.agents.find((a) => a.agent === 'nuclei')
  check('open claims do not enter the denominator', n?.sample === 1, n)
  check('open claims are still counted', n?.open === 2, n)
  check('reported counts every claim it touched', n?.reported === 3, n)
}

// ── 5. 样本不足不给比率
{
  const claims = [
    claim('c1', 'confirmed', [ev('a')]),
    claim('c2', 'refuted', [ev('a')], ['a']),
  ]
  const r = analyzePrecision(claims)
  const a = r.agents.find((x) => x.agent === 'a')
  check('small sample yields no ratio', a?.falsePositiveRate === undefined, a)
  check('and says why', typeof a?.note === 'string' && a.note.includes('sample'), a?.note)

  // 补到阈值就有数了
  const many = []
  for (let i = 0; i < MIN_SAMPLE; i += 1) many.push(claim(`k${i}`, 'confirmed', [ev('a')]))
  many.push(claim('bad1', 'refuted', [ev('a')], ['a']))
  many.push(claim('bad2', 'refuted', [ev('a')], ['a']))
  const r2 = analyzePrecision(many)
  const a2 = r2.agents.find((x) => x.agent === 'a')
  check('enough sample produces a ratio', typeof a2?.falsePositiveRate === 'number', a2)
  check('ratio uses settled as denominator', Math.abs((a2?.falsePositiveRate ?? 0) - 2 / 7) < 1e-9, a2?.falsePositiveRate)
}

// ── 6. 排序：最该被审视的排最上面
{
  const bad = []
  for (let i = 0; i < MIN_SAMPLE; i += 1) bad.push(claim(`b${i}`, 'refuted', [ev('noisy')], ['noisy']))
  for (let i = 0; i < MIN_SAMPLE; i += 1) bad.push(claim(`g${i}`, 'confirmed', [ev('solid')]))
  const r = analyzePrecision(bad)
  check('worst offender sorts first', r.agents[0]?.agent === 'noisy', r.agents.map((a) => a.agent))
}

// ── 7. 提示只提示，不自动弃用
{
  const claims = []
  for (let i = 0; i < MIN_SAMPLE; i += 1) claims.push(claim(`r${i}`, 'refuted', [ev('noisy')], ['noisy']))
  const actions = precisionActions(analyzePrecision(claims))
  check('high false-positive rate produces an action', actions.length >= 1, actions)
  check('the action points at the criteria, not at disabling',
    actions.some((a) => a.includes('判据') || a.includes('verdict')), actions)

  const clean = analyzePrecision([claim('c1', 'confirmed', [ev('ok')])])
  check('nothing to say when sample is thin', precisionActions(clean).some((a) => a.includes('还不能用') || a.includes('claim')), precisionActions(clean))
}

// ── 8. 空数据不炸
{
  const r = analyzePrecision([])
  check('empty ledger is empty not broken', r.agents.length === 0 && r.totalClaims === 0, r)
  check('empty ledger has no actions', precisionActions(r).length === 0, precisionActions(r))
}

// ── 9. 端到端：真 ClaimStore 走一遍 refute 归因
{
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const { ClaimStore } = await import('../dist/provenance-tools.js')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-precision-'))
  const storePath = path.join(dir, 'claims.jsonl')

  const store = new ClaimStore(undefined, { strictRelevance: false, storePath })
  const c = store.assert('目标存在暴露的 .env 文件')
  store.attach(c.id, {
    ref: 'evidence/nuclei/stdout.log',
    pathKey: 'task:agent:nuclei',
    source: { kind: 'worker', taskId: 't1', argv: ['nuclei', '-u', 'http://x'], cwd: '/tmp' },
    baselineDigest: 'd',
  })
  check('evidence source survives attach', store.get(c.id)?.evidence[0]?.source?.argv[0] === 'nuclei')

  const refuted = store.refute(c.id, { ref: 'evidence/curl/stderr.log', pathKey: 'task:agent:curl' }, ['nuclei'])
  check('refute records the blame', JSON.stringify(refuted?.blame) === JSON.stringify(['nuclei']), refuted?.blame)
  check('claim is terminal', refuted?.status === 'refuted')

  const report = analyzePrecision(store.query())
  const n = report.agents.find((a) => a.agent === 'nuclei')
  check('the ledger sees the refuted report', n?.refuted === 1, n)

  // 归因必须能跨进程活下来
  const reloaded = new ClaimStore(undefined, { strictRelevance: false, storePath })
  const back = reloaded.get(c.id)
  check('blame survives a snapshot reload', JSON.stringify(back?.blame) === JSON.stringify(['nuclei']), back?.blame)

  // 归因可修正：记错了第二次 refute 覆盖，而不是叠加
  store.refute(c.id, undefined, ['semgrep'])
  check('a second refute replaces the blame', JSON.stringify(store.get(c.id)?.blame) === JSON.stringify(['semgrep']), store.get(c.id)?.blame)
  const r3 = analyzePrecision(store.query())
  check('the corrected blame moves the entry', (r3.agents.find((a) => a.agent === 'nuclei')?.refuted ?? 0) === 0, r3.agents)
  store.refute(c.id, undefined, ['nuclei'])

  // 不带归因的推翻：记 claim，不记人
  const c2 = store.assert('接口存在越权')
  store.attach(c2.id, {
    ref: 'e2', pathKey: 'pk2',
    source: { kind: 'worker', taskId: 't2', argv: ['ffuf', '-u', 'http://x'], cwd: '/tmp' },
  })
  store.refute(c2.id)
  const r2 = analyzePrecision(store.query())
  check('unattributed refute does not blame the tool', r2.agents.find((a) => a.agent === 'ffuf')?.refuted === 0, r2.agents)
  check('unattributed refute is counted as invisible', r2.unattributedRefutations >= 1, r2.unattributedRefutations)

  fs.rmSync(dir, { recursive: true, force: true })
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
