/**
 * ARTEX adapter 验收（不连真服务，用假 client 验状态映射）。
 *
 * 关键：ARTEX 的 task 状态要能正确翻译成我们的四种终态，
 * 尤其是「跑完了但没有 findings」——那是 settled，不是失败。
 */
import { createArtexAdapter } from '../dist/council/artex-adapter.js'
import { AdapterRegistry } from '../dist/council/contract.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const contract = (over = {}) => ({
  id: 't1', kind: 'agent', direction: 'web-pentest', target: 'http://x',
  estimatedCost: 3, requestedBy: 'marshal', rationale: 'probe', timeoutMs: 60_000, ...over,
})

const fakeClient = (task) => ({
  async health() { return true },
  async createTask() { return { id: 'task-1', status: 'created' } },
  async getTask() { return task },
})

// ── 1. 跑完无发现 = settled
{
  const a = createArtexAdapter(fakeClient({ id: 'task-1', status: 'done', findings: {} }))
  const r = await a.execute(contract(), { signal: new AbortController().signal })
  check('done without findings is settled', r.outcome === 'settled', r)
  check('and reports not found', r.found === false, r)
  check('detail mentions zero findings', /no findings/.test(r.detail ?? ''), r.detail)
}

// ── 2. 跑完有发现 = settled + found
{
  const a = createArtexAdapter(fakeClient({ id: 'task-1', status: 'done', findings: { high: 2, low: 1 } }))
  const r = await a.execute(contract(), { signal: new AbortController().signal })
  check('done with findings is settled', r.outcome === 'settled')
  check('found is true', r.found === true, r)
  check('detail carries the severity split', /high=2/.test(r.detail ?? ''), r.detail)
  check('evidence location is disclosed', /artex task task-1/.test(r.detail ?? ''), r.detail)
}

// ── 3. 失败任务 = failed
{
  const a = createArtexAdapter(fakeClient({ id: 'task-1', status: 'failed' }))
  const r = await a.execute(contract(), { signal: new AbortController().signal })
  check('failed task maps to failed', r.outcome === 'failed', r)
  check('reason names the state', /failed/.test(r.reason ?? ''), r.reason)
}

// ── 4. 创建失败不抛，返回 failed
{
  const a = createArtexAdapter({
    async health() { return false },
    async createTask() { throw new Error('connection refused') },
    async getTask() { throw new Error('unreachable') },
  })
  const r = await a.execute(contract(), { signal: new AbortController().signal })
  check('create failure is a result not an exception', r.outcome === 'failed', r)
  check('reason includes the underlying error', /connection refused/.test(r.reason ?? ''), r.reason)
}

// ── 5. 适配器可注册为 agent kind
{
  const reg = new AdapterRegistry()
  reg.register(createArtexAdapter(fakeClient({ id: 't', status: 'done' })))
  check('registers under agent kind', reg.resolve('agent') !== undefined)
  check('describe mentions ARTEX', /ARTEX/.test(reg.describe().find((d) => d.kind === 'agent')?.describe ?? ''))
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
