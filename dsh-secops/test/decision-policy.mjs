/**
 * 阶段 K 验收：决策纪律。
 *
 * 三条规则都基于**可观测的决策流**，不试图判断"决策对不对"：
 *   1. 拒绝必须说清理由（长度阈值）
 *   2. 同一理由连续出现 = 卡死
 *   3. 连续多步只拒绝不前进 = 空转
 */

import {
  DecisionPolicy,
  MIN_REASON_LENGTH,
  REPEAT_WINDOW,
  STALL_WINDOW,
} from '../dist/decision-policy.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const reject = (policy, reason, step = 1, agent = 'a1') =>
  policy.observe({ turn: 1, step, agentId: agent, kind: 'reject', reason })
const enter = (policy, step = 1, agent = 'a1') =>
  policy.observe({ turn: 1, step, agentId: agent, kind: 'enter' })

// ── 1. 空理由
{
  const p = new DecisionPolicy()
  const v = reject(p, 'no')
  check('short reason flagged', v.some((x) => x.code === 'EMPTY_REASON'), v)
  check('hint is actionable', String(v[0]?.hint).includes('state the concrete'), v[0])
  check('audit counts it', p.audit().emptyReasons === 1, p.audit())

  const p2 = new DecisionPolicy()
  const ok = reject(p2, 'target returned 403 consistently across three probes')
  check('substantive reason passes', ok.length === 0, ok)
}

// ── 2. 重复理由 = 卡死
{
  const p = new DecisionPolicy()
  const reason = 'the endpoint keeps returning 403 so the probe cannot proceed'
  reject(p, reason)
  reject(p, reason)
  const third = reject(p, reason)
  check(`repeat threshold ${REPEAT_WINDOW} triggers`, third.some((x) => x.code === 'REPEATED_REJECTION'), third)
  check('hint says change the method', String(third.find((x) => x.code === 'REPEATED_REJECTION')?.hint).includes('change the method'))

  // 不同理由不算重复
  const p2 = new DecisionPolicy()
  reject(p2, 'first distinct blocking condition here')
  reject(p2, 'second distinct blocking condition here')
  const r3 = reject(p2, 'third distinct blocking condition here')
  check('distinct reasons do not trigger repeat', !r3.some((x) => x.code === 'REPEATED_REJECTION'), r3)
}

// ── 3. 连续拒绝 = 空转
{
  const p = new DecisionPolicy()
  let last = []
  for (let i = 0; i < STALL_WINDOW; i++) {
    // 理由各不相同，排除"重复"规则干扰
    last = reject(p, `blocking condition number ${'abcdefg'[i]} prevents progress`, i + 1)
  }
  check(`stall threshold ${STALL_WINDOW} triggers`, last.some((x) => x.code === 'STALLED'), last)
  check('stall hint hands back to operator', String(last.find((x) => x.code === 'STALLED')?.hint).includes('operator'))
  check('verdict is stalled', p.audit().verdict === 'stalled', p.audit().verdict)
}

// ── 4. enter 重置连续计数
{
  const p = new DecisionPolicy()
  reject(p, 'blocking condition one blocks the probe', 1)
  reject(p, 'blocking condition one blocks the probe', 2)
  enter(p, 3)
  const after = reject(p, 'blocking condition one blocks the probe', 4)
  check('enter resets repeat counter', !after.some((x) => x.code === 'REPEATED_REJECTION'), after)
  check('enter resets stall counter', p.audit().worstStall === 2, p.audit().worstStall)
}

// ── 5. 审计报告结构
{
  const p = new DecisionPolicy()
  enter(p, 1)
  enter(p, 2)
  reject(p, 'one concrete blocking condition here', 3)
  const a = p.audit()
  check('totals correct', a.total === 3 && a.entered === 2 && a.rejected === 1, a)
  check('verdict ok when reasons are fine', a.verdict === 'ok', a.verdict)
  check('violations empty', a.violations.length === 0, a.violations)
}

// ── 6. 多 agent 隔离
{
  const p = new DecisionPolicy()
  const reason = 'same wording used by two different agents here'
  reject(p, reason, 1, 'agent-a')
  reject(p, reason, 1, 'agent-b')
  const third = reject(p, reason, 2, 'agent-a')
  // agent-a 自己才 2 次，未达阈值；agent-b 只有 1 次
  check('repeat is per-agent', !third.some((x) => x.code === 'REPEATED_REJECTION'), third)
}

// ── 7. 空理由也计入审计
{
  const p = new DecisionPolicy()
  reject(p, '')
  reject(p, 'x')
  const a = p.audit()
  check('empty reasons counted', a.emptyReasons === 2, a.emptyReasons)
  check('verdict degraded', a.verdict === 'degraded', a.verdict)
  check('MIN_REASON_LENGTH exported', typeof MIN_REASON_LENGTH === 'number')
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
