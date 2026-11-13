/** 阶段 C 集成：claim 快照写入 session log 并由 projection 折叠。 */
import { Context } from '@deepseek-ai/cordis'
import SessionStore from '@deepseek-ai/dsh-session'
import Projections from '@deepseek-ai/dsh-session-projection'
import { ClaimStore } from '../dist/provenance-tools.js'
import { registerProvenanceProjection, readProvenance } from '../dist/provenance.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const ctx = new Context()
ctx.plugin(SessionStore)
ctx.plugin(Projections)
await sleep(700)
check('services loaded', !!ctx.get('sessions') && !!ctx.get('sessionProjections'))

await registerProvenanceProjection(ctx.sessionProjections)
const session = ctx.sessions.create()

const store = new ClaimStore(session)
const c = store.assert('POST /api/transfer 接受负数金额', { falsifier: '负数被服务端拒绝则假设不成立' })
store.attach(c.id, { ref: 'evidence://a', pathKey: 'http:differential', executed: 'curl -X POST http://t/api/transfer -d amount=-5' })
store.attach(c.id, { ref: 'evidence://b', pathKey: 'tool:recompute', executed: 'recompute POST /api/transfer amount=-5 balance' })
await sleep(500)

const state = readProvenance(ctx.sessionProjections, session)
check('claims folded', state?.claims?.length === 1, state)
check('status confirmed via two paths', state?.claims?.[0]?.status === 'confirmed', state?.claims?.[0])
check('confirmedCount', state?.confirmedCount === 1, state?.confirmedCount)

const c2 = store.assert('GET /admin 可未授权访问')
store.refute(c2.id, { ref: 'evidence://c', pathKey: 'http:differential' })
await sleep(400)
const state2 = readProvenance(ctx.sessionProjections, session)
check('refuted claim counted', state2?.refutedCount === 1, state2?.refutedCount)
check('two claims present', state2?.claims?.length === 2, state2?.claims?.length)

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
