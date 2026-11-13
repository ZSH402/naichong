/** 阶段 A 验收：决策记录写入 → projection 折叠 → 读回。 */
import { Context } from '@deepseek-ai/cordis'
import SessionStore from '@deepseek-ai/dsh-session'
import Projections from '@deepseek-ai/dsh-session-projection'
import { registerDecisionProjection, recordDecision, readDecisions } from '../dist/decision-record.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const ctx = new Context()
ctx.plugin(SessionStore)
ctx.plugin(Projections)
await sleep(800)
check('sessions service', !!ctx.get('sessions'))
check('sessionProjections service', !!ctx.get('sessionProjections'))

await registerDecisionProjection(ctx.sessionProjections)
check('projection registered', true)

const session = ctx.sessions.create()
check('session created', !!session)

const seq1 = recordDecision(session, {
  decisionId: 'd-1', turn: 1, step: 1, agentId: 'a1', kind: 'enter',
  candidates: [], evidenceRefs: [], rejected: [],
})
const seq2 = recordDecision(session, {
  decisionId: 'd-2', turn: 1, step: 9, agentId: 'a1', kind: 'reject',
  reason: 'step exceeds maxSteps', candidates: [], evidenceRefs: [], rejected: [],
})
check('both records committed to log', Number.isFinite(seq1) && Number.isFinite(seq2) && seq2 > seq1, { seq1, seq2 })
await sleep(500)

const st = readDecisions(ctx.sessionProjections, session)
check('decisions folded', st?.decisions?.length === 2, st)
check('entered counted', st?.enteredCount === 1, st?.enteredCount)
check('rejected counted', st?.rejectedCount === 1, st?.rejectedCount)
check('lastTurn tracked', st?.lastTurn === 1, st?.lastTurn)
check('reason persisted', st?.decisions?.[1]?.reason === 'step exceeds maxSteps', st?.decisions?.[1])

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
