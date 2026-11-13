/**
 * 三公验收：丞相（分析）/ 太尉（调度）/ 御史大夫（风控）。
 *
 * 重点在三处容易写松的地方：
 *   一、预扣而不是事后扣——否则并发派活双双过检查、一起超支
 *   二、被驳回的任务不拖垮整个计划——其他方向照跑
 *   三、证据清单的哈希真的随内容变化——否则「原始证据及哈希」只是一张纸
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Censor, CENSOR_DEFAULTS } from '../dist/council/censor.js'
import { Chancellor } from '../dist/council/chancellor.js'
import { Marshal } from '../dist/council/marshal.js'
import { AdapterRegistry, buildEvidenceManifest, manifestDigest, nextTaskId } from '../dist/council/contract.js'
import { createWorkerAdapter } from '../dist/council/adapters.js'
import { Roster } from '../dist/council/roster.js'
import { AgentRegistry } from '../dist/agent-registry.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-council-'))

const contract = (over = {}) => ({
  id: nextTaskId('web-pentest', 'code-tool'),
  kind: 'code-tool',
  direction: 'web-pentest',
  target: 'https://example.test',
  estimatedCost: 3,
  requestedBy: 'marshal',
  rationale: 'test',
  ...over,
})

// ── 1. 御史大夫：授权范围
{
  const c = new Censor({ allowedHosts: ['example.test'] })
  check('in-scope host approved', c.authorize(contract({ target: 'https://example.test/a' })).allowed === true)
  const out = c.authorize(contract({ target: 'https://evil.test/a' }))
  check('out-of-scope host denied', out.allowed === false && out.code === 'scope', out)
  const unknown = c.authorize(contract({ target: 'local file /tmp/x' }))
  check('undeterminable host denied when a scope is set', unknown.allowed === false && unknown.code === 'scope', unknown)
  check('denials are tallied', c.ledger().blocked.some((b) => b.code === 'scope' && b.count === 2), c.ledger().blocked)

  // 无范围约束时不该拦任何东西
  const open = new Censor({})
  check('unrestricted policy allows anything', open.authorize(contract({ target: 'https://whatever.test' })).allowed === true)
}

// ── 2. 御史大夫：限流按已执行计数，不按审批计数
{
  let now = 1000
  const c = new Censor({ rateMaxPerWindow: 2, rateWindowMs: 1000 }, { now: () => now })
  const run = () => {
    const t = contract()
    const a = c.authorize(t)
    if (a.allowed) c.settle(t, 'ok')
    return a
  }
  check('first allowed', run().allowed === true)
  check('second allowed', run().allowed === true)
  const third = c.authorize(contract())
  check('third hits the rate limit', third.allowed === false && third.code === 'rate-limit', third)
  // 只审批不执行不占窗口
  now += 1001
  check('window slides and allows again', c.authorize(contract()).allowed === true)
  check('approved-but-not-run does not consume the window',
    c.ledger().runs.find((r) => r.direction === 'web-pentest')?.inWindow === 0, c.ledger().runs)
}

// ── 3. 御史大夫：熔断只看故障
{
  const c = new Censor({ rateMaxPerWindow: 999, breakerThreshold: 2, breakerCooldownMs: 5000 })
  const fault = () => {
    const t = contract()
    c.authorize(t)
    c.settle(t, 'fault')
  }
  fault()
  check('one fault does not open the breaker', c.authorize(contract()).allowed === true)
  fault()
  const blocked = c.authorize(contract())
  check('breaker opens after repeated faults', blocked.allowed === false && blocked.code === 'breaker-open', blocked)
  check('breaker is listed in the ledger', c.ledger().openBreakers.length === 1, c.ledger().openBreakers)
}

// ── 4. 御史大夫：未定论不熔断
{
  const c = new Censor({ rateMaxPerWindow: 999, breakerThreshold: 2 })
  for (let i = 0; i < 4; i += 1) {
    const t = contract()
    c.authorize(t)
    c.settle(t, 'neutral')
  }
  check('inconclusive does not trip the breaker', c.ledger().openBreakers.length === 0, c.ledger().openBreakers)
  check('but the runs are still counted', c.ledger().runs[0]?.runs === 4, c.ledger().runs)
}

// ── 5. 御史大夫：超时兜底
{
  const c = new Censor({ maxTaskTimeoutMs: 10_000 })
  const tooLong = c.authorize(contract({ timeoutMs: 60_000 }))
  check('oversized timeout is denied', tooLong.allowed === false && tooLong.code === 'timeout-too-large', tooLong)
  check('a sane timeout passes', c.authorize(contract({ timeoutMs: 5_000 })).allowed === true)
}

// ── 6. 丞相：假设生成
{
  const registry = new AgentRegistry([
    { id: 'web-agent', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10 },
    { id: 'code-agent', direction: 'code-audit', kind: 'cli', capability: 'x', accepts: ['directory'], priority: 10 },
  ])
  const claims = [
    { id: 'c1', claim: '订单接口存在越权', status: 'hypothesis', evidenceCount: 1, independentPaths: 1 },
  ]
  const chancellor = new Chancellor({
    registry,
    knowledge: { claims: () => claims, lastDispatch: () => undefined },
  })
  const a = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest', 'code-audit'] })
  check('shape detected for assessment', a.shape === 'url')
  const gap = a.hypotheses.filter((h) => h.origin === 'coverage-gap')
  check('only directions that accept the shape produce hypotheses',
    gap.length === 1 && gap[0].direction === 'web-pentest', gap.map((g) => g.direction))
  const weak = a.hypotheses.filter((h) => h.origin === 'weak-evidence')
  check('single-path claim yields a weak-evidence hypothesis', weak.length === 1, weak)
  check('every hypothesis carries a falsifier', a.hypotheses.every((h) => h.falsifiableBy.length > 10))

  const a2 = chancellor.assess({
    target: 'https://example.test',
    directions: ['web-pentest'],
    manual: [{ statement: '登录接口可爆破', falsifiableBy: '超阈值尝试仍返回正常响应即不成立', direction: 'web-pentest' }],
  })
  check('manual hypothesis is included verbatim', a2.hypotheses.some((h) => h.statement === '登录接口可爆破'))
}

// ── 7. 丞相：无可用 agent 时给 blocker 而不是空假设
{
  const registry = new AgentRegistry([])
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] } })
  const a = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest'] })
  check('no candidates means no hypotheses', a.hypotheses.length === 0)
  check('an explicitly requested empty direction is reported as a blocker',
    a.blockers.length === 1 && a.blockers[0].includes('web-pentest'), a.blockers)

  // 自动铺开时不报缺口：给二进制目标报「web 工具吃不下 binary」是显而易见的废话，
  // 那种输出会淹掉真正有用的假设。
  const auto = chancellor.assess({ target: 'https://example.test' })
  check('auto-expanded assessment stays quiet about mismatched directions', auto.blockers.length === 0, auto.blockers)
}

// ── 7c. 丞相读覆盖账本：查过的方向不再生成假设
{
  const registry = new AgentRegistry([
    { id: 'web-agent', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10 },
    { id: 'code-agent', direction: 'code-audit', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10 },
  ])
  const stamped = []
  const coverage = {
    of(asset, checks) {
      const check = checks?.[0] ?? ''
      return {
        state: stamped.includes(check) ? 'covered' : 'not-scanned',
        verdict: stamped.includes(check) ? '已覆盖' : '未扫描',
        gaps: stamped.includes(check) ? [] : [check],
      }
    },
  }
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] }, coverage })
  const before = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest', 'code-audit'] })
  check('uncovered directions produce hypotheses', before.hypotheses.length === 2, before.hypotheses.length)
  check('nothing skipped when nothing is covered', before.skipped.length === 0, before.skipped)

  stamped.push('web-pentest')
  const after = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest', 'code-audit'] })
  check('covered direction no longer produces a hypothesis',
    after.hypotheses.every((h) => h.direction !== 'web-pentest'), after.hypotheses.map((h) => h.direction))
  check('and it is reported as skipped', after.skipped.some((s) => s.direction === 'web-pentest'), after.skipped)
  check('the uncovered direction still gets one', after.hypotheses.some((h) => h.direction === 'code-audit'))
}

// ── 7b. 弱证据假设的方向来自形态反查，不是默认值
{
  const registry = new AgentRegistry([
    { id: 'bin-agent', direction: 'binary-reverse', kind: 'cli', capability: 'x', accepts: ['binary'], priority: 10 },
  ])
  const claims = [{ id: 'c1', claim: '该二进制启用了 NX', status: 'hypothesis', evidenceCount: 1, independentPaths: 1 }]
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => claims } })
  const a = chancellor.assess({ target: '/usr/bin/ls' })
  const weak = a.hypotheses.find((h) => h.origin === 'weak-evidence')
  check('weak-evidence direction is inferred from shape', weak?.direction === 'binary-reverse', weak?.direction)
  check('inference is disclosed in the rationale', /反查/.test(weak?.rationale ?? ''), weak?.rationale)

  const empty = new AgentRegistry([])
  const c2 = new Chancellor({ registry: empty, knowledge: { claims: () => claims } })
  const a2 = c2.assess({ target: '/usr/bin/ls' })
  check('no direction can verify it means a blocker, not a wrong guess',
    a2.hypotheses.every((h) => h.origin !== 'weak-evidence') && a2.blockers.some((b) => b.includes('复核方向')),
    a2.blockers)
}

// ── 8. 太尉：计划与执行
{
  const registry = new AgentRegistry([
    { id: 'web-agent', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10, cost: 'cheap' },
    { id: 'audit-agent', direction: 'code-audit', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10, cost: 'cheap' },
  ])
  const censor = new Censor({ rateMaxPerWindow: 100 })
  const adapters = new AdapterRegistry()
  const ran = []
  adapters.register(
    createWorkerAdapter({
      handlers: new Map([
        [
          'web-pentest',
          async () => {
            ran.push('web-pentest')
            return { found: true, detail: 'boom', evidenceDir: undefined }
          },
        ],
        [
          'code-audit',
          async () => {
            ran.push('code-audit')
            throw new Error('worker exploded')
          },
        ],
      ]),
    }),
  )

  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] } })
  const assessment = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest', 'code-audit'] })
  const marshal = new Marshal({ registry, adapters, censor })
  const plan = marshal.plan(assessment, {})
  check('plan turns hypotheses into tasks', plan.tasks.length === assessment.hypotheses.length, plan.tasks.length)
  check('plan picks the worker adapter when available', plan.tasks.every((t) => t.adapter === 'worker'))

  const summary = await marshal.execute(plan, new AbortController().signal)
  check('executes every planned task', summary.results.length === plan.tasks.length)
  check('worker failure is captured not thrown', summary.failed === 1, summary)
  check('found result counted', summary.found === 1, summary)
  check('board has entries for all tasks', marshal.boardEntries().length === plan.tasks.length)
}

// ── 8b. 太尉：同方向多条任务轮转分配，不重复压同一个 agent
{
  const registry = new AgentRegistry([
    { id: 'a1', direction: 'binary-reverse', kind: 'cli', capability: 'x', accepts: ['binary'], priority: 10, cost: 'cheap' },
    { id: 'a2', direction: 'binary-reverse', kind: 'cli', capability: 'x', accepts: ['binary'], priority: 20, cost: 'cheap' },
  ])
  const censor = new Censor({ rateMaxPerWindow: 100 })
  const adapters = new AdapterRegistry()
  adapters.register(createWorkerAdapter({ handlers: new Map([['binary-reverse', async () => ({ found: false })]]) }))
  const chancellor = new Chancellor({
    registry,
    knowledge: {
      claims: () => [
        { id: 'c1', claim: '断言一', status: 'hypothesis', evidenceCount: 1, independentPaths: 1, lastDirection: 'binary-reverse' },
        { id: 'c2', claim: '断言二', status: 'hypothesis', evidenceCount: 1, independentPaths: 1, lastDirection: 'binary-reverse' },
      ],
    },
  })
  const assessment = chancellor.assess({ target: '/usr/bin/ls', directions: ['binary-reverse'] })
  const marshal = new Marshal({ registry, adapters, censor })
  const plan = marshal.plan(assessment, {})
  const picks = plan.tasks.map((t) => t.contract.preferredAgentId)
  check('rotation spreads tasks across candidates', new Set(picks).size === 2, picks)
  check('rotation stays inside agents that accept the shape', picks.every((p) => p === 'a1' || p === 'a2'), picks)
}

// ── 9. 太尉：御史驳一条不影响其他条
{
  const registry = new AgentRegistry([
    { id: 'a', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10, cost: 'cheap' },
    { id: 'b', direction: 'code-audit', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10, cost: 'cheap' },
  ])
  // 只给 code-audit 额度：web-pentest 那条应被预算拦下
  const censor = new Censor({ rateMaxPerWindow: 100 })
  const adapters = new AdapterRegistry()
  const ran = []
  adapters.register(
    createWorkerAdapter({
      handlers: new Map([['code-audit', async () => { ran.push('code-audit'); return { found: false } }]]),
    }),
  )
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] } })
  const assessment = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest', 'code-audit'] })
  const marshal = new Marshal({ registry, adapters, censor })
  const plan = marshal.plan(assessment, {})

  const summary = await marshal.execute(plan, new AbortController().signal)
  // web-pentest 没有 worker handler → refused；code-audit 正常跑
  check('missing handler is refused, not a crash', summary.results.some((r) => r.outcome === 'refused'))
  check('the healthy direction still ran', ran.includes('code-audit'), ran)
}

// ── 10. 证据清单与哈希
{
  const dir = path.join(tmpRoot, 'ev-1')
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'stdout.log'), 'first')
  const m1 = buildEvidenceManifest(dir)
  const e1 = m1.entries.find((e) => e.path === 'stdout.log')
  check('manifest has a sha256 per file', typeof e1?.sha256 === 'string' && e1.sha256.length === 64, e1)
  check('manifest records size', e1?.size === 5, e1)
  check('manifest is written next to the evidence', fs.existsSync(path.join(dir, 'manifest.json')))

  const d1 = manifestDigest(m1)
  fs.writeFileSync(path.join(dir, 'stdout.log'), 'second')
  const m2 = buildEvidenceManifest(dir)
  check('changing content changes the digest', manifestDigest(m2) !== d1)
  check('changing content does not change the path', m2.entries.find((e) => e.path === 'stdout.log')?.path === 'stdout.log')

  // 子目录也要进去
  fs.mkdirSync(path.join(dir, 'nested'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'nested', 'x.txt'), 'y')
  const m3 = buildEvidenceManifest(dir)
  check('nested files are walked', m3.entries.some((e) => e.path === 'nested/x.txt'), m3.entries.map((e) => e.path))
}

// ── 11. 人才档案
{
  const p = path.join(tmpRoot, 'roster.jsonl')
  const r = new Roster(p)
  r.record({ agentId: 'corvus', outcome: 'settled', shape: 'command', found: true, durationMs: 5000 })
  r.record({ agentId: 'corvus', outcome: 'failed', shape: 'command', fault: 'timed out', durationMs: 1000 })
  check('roster tracks runs', r.get('corvus')?.runs === 2)
  check('roster tracks found', r.get('corvus')?.foundCount === 1)
  check('roster tracks per-shape stats', r.get('corvus')?.byShape['command']?.runs === 2)
  check('small samples do not produce a score', r.successScore('corvus') === undefined)

  r.persist()
  const r2 = new Roster(p)
  check('roster survives a reload', r2.get('corvus')?.runs === 2)
}

// ── 11b. 任务板能跨实例恢复
{
  const boardPath = path.join(tmpRoot, 'board.jsonl')
  const registry = new AgentRegistry([
    { id: 'a', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10 },
  ])
  const adapters = new AdapterRegistry()
  adapters.register(createWorkerAdapter({ handlers: new Map([['web-pentest', async () => ({ found: true })]]) }))
  const censor = new Censor({ rateMaxPerWindow: 100 })
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] } })
  const assessment = chancellor.assess({ target: 'https://example.test', directions: ['web-pentest'] })
  const m1 = new Marshal({ registry, adapters, censor, boardPath })
  await m1.execute(m1.plan(assessment, {}), new AbortController().signal)
  const before = m1.boardEntries().length
  check('board has entries after a run', before > 0, before)

  const m2 = new Marshal({ registry, adapters, censor: new Censor({ rateMaxPerWindow: 100 }), boardPath })
  check('board is restored by a fresh instance', m2.boardEntries().length === before, m2.boardEntries().length)
}

// ── 11c. 契约里的超时必须是确定值
{
  const registry = new AgentRegistry([
    { id: 'slow', direction: 'web-pentest', kind: 'cli', capability: 'x', accepts: ['url'], priority: 10, defaultTimeoutMs: 900_000 },
  ])
  const adapters = new AdapterRegistry()
  const marshal = new Marshal({ registry, adapters, censor: new Censor({}) })
  const chancellor = new Chancellor({ registry, knowledge: { claims: () => [] } })
  const plan = marshal.plan(chancellor.assess({ target: 'https://example.test', directions: ['web-pentest'] }), {})
  check('planned contracts always carry a timeout', plan.tasks.every((t) => typeof t.contract.timeoutMs === 'number'), plan.tasks.map((t) => t.contract.timeoutMs))
  check('the timeout comes from the candidate', plan.tasks[0]?.contract.timeoutMs === 900_000, plan.tasks[0]?.contract.timeoutMs)
}

// ── 12. 策略快照
{
  check('default policy caps a single task timeout', CENSOR_DEFAULTS.maxTaskTimeoutMs > 0)
  check('default policy has no budget fields at all', !('totalBudget' in CENSOR_DEFAULTS) && !('perDirectionBudget' in CENSOR_DEFAULTS))
}

fs.rmSync(tmpRoot, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
