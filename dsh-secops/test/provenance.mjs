/**
 * 阶段 C 验收：provenance 的独立复现判据。
 *
 * 核心断言：一条 claim 要 confirmed 必须有 ≥2 条**不同 pathKey** 的证据；
 * 同 pathKey 的重复证据不计数。这是与「网络来源=不可信」的根本区别。
 */

import { ClaimStore } from '../dist/provenance-tools.js'
import { CONFIRM_THRESHOLD, deriveStatus, isSettled, newClaim, withEvidence } from '../dist/provenance.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

// ── 1. 纯函数：状态推导
{
  const empty = newClaim('该接口仅依据客户端提交的 authCode 判定权限')
  check('new claim starts as hypothesis', empty.status === 'hypothesis', empty.status)

  const one = withEvidence(empty, { ref: 'e1', pathKey: 'http:differential', addedAt: 1 })
  check('one path => partial', one.status === 'partial', one.status)
  check('independentPaths counted', one.independentPaths === 1, one.independentPaths)

  const samePath = withEvidence(one, { ref: 'e2', pathKey: 'http:differential', addedAt: 2 })
  check('same pathKey does not count twice', samePath.independentPaths === 1, samePath.independentPaths)
  check('same pathKey stays partial', samePath.status === 'partial', samePath.status)

  const twoPaths = withEvidence(samePath, { ref: 'e3', pathKey: 'tool:recompute', addedAt: 3 })
  check(`two distinct paths => confirmed (threshold ${CONFIRM_THRESHOLD})`, twoPaths.status === 'confirmed', twoPaths.status)
  check('isSettled for confirmed', isSettled(twoPaths) === true)

  check('deriveStatus refuted wins', deriveStatus(twoPaths.evidence, { refuted: true }) === 'refuted')
  check('deriveStatus inference', deriveStatus([], { inference: true }) === 'inference')

  // 同 ref 幂等
  const dup = withEvidence(twoPaths, { ref: 'e3', pathKey: 'tool:recompute', addedAt: 4 })
  check('duplicate evidence is idempotent', dup === twoPaths, { size: dup.evidence.length })
}

// ── 2. ClaimStore：完整生命周期
{
  const store = new ClaimStore()
  const c = store.assert('GET /api/order?id= 未校验归属', { falsifier: '用他人 id 请求若返回 403 则假设不成立' })
  check('assert creates claim', c.status === 'hypothesis', c.status)
  check('id is derived from text', c.id.startsWith('claim-'), c.id)

  const again = store.assert('GET /api/order?id= 未校验归属')
  check('assert is idempotent by text', again.id === c.id && store.query().length === 1)

  store.attach(c.id, { ref: 'evidence://req-1', pathKey: 'http:idor', executed: 'curl http://t/api/order?id=2', executedTrusted: true })
  check('after one evidence => partial', store.get(c.id)?.status === 'partial', store.get(c.id)?.status)

  store.attach(c.id, { ref: 'evidence://req-2', pathKey: 'http:idor', executed: 'curl http://t/api/order?id=3', executedTrusted: true })
  check('second same-path evidence keeps partial', store.get(c.id)?.status === 'partial', store.get(c.id)?.status)

  store.attach(c.id, { ref: 'evidence://req-3', pathKey: 'role:other-user', executed: 'curl -H Cookie:other http://t/api/order?id=4', executedTrusted: true })
  check('cross-path evidence => confirmed', store.get(c.id)?.status === 'confirmed', store.get(c.id)?.status)

  const settled = store.settledIds()
  check('settledIds lists confirmed', settled.includes(c.id), settled)
}

// ── 3. 证伪是单向闸门
{
  const store = new ClaimStore()
  const c = store.assert('PUT /api/user 允许把 role 改成 admin')
  store.attach(c.id, { ref: 'e1', pathKey: 'http:differential', executed: 'curl -X PUT http://t/api/user -d role=admin', executedTrusted: true })
  store.refute(c.id, { ref: 'e2', pathKey: 'http:differential', note: '服务端校验拒绝' })
  check('refuted status set', store.get(c.id)?.status === 'refuted', store.get(c.id)?.status)

  // 后续新证据不应把它翻回 confirmed
  store.attach(c.id, { ref: 'e3', pathKey: 'tool:recompute' })
  store.attach(c.id, { ref: 'e4', pathKey: 'role:admin' })
  check('refutation is terminal (not promoted back)', store.get(c.id)?.status === 'refuted', store.get(c.id)?.status)

  const queried = store.query({ settledOnly: true })
  check('settled query returns refuted', queried.some((x) => x.id === c.id && x.status === 'refuted'), queried.map((x) => x.status))
}

// ── 4. 不同 claim 互不干扰
{
  const store = new ClaimStore()
  const a = store.assert('claim A')
  const b = store.assert('claim B')
  store.attach(a.id, { ref: 'x', pathKey: 'p1', executed: 'claim A probe', executedTrusted: true })
  check('B untouched by A evidence', store.get(b.id)?.independentPaths === 0, store.get(b.id))
  check('two claims tracked', store.query().length === 2)
}

// ── 5. 相关性闸：无关证据被拒（这是端到端里模型暴露的问题）
{
  const store = new ClaimStore()
  const c = store.assert('PUT /api/user 允许修改他人角色')
  check('claim created', c.status === 'hypothesis')

  const unrelated = store.attach(c.id, {
    ref: 'task:probe',
    pathKey: 'task:probe',
    executed: 'node -e "console.log(7)"', executedTrusted: true,
  })
  check('unrelated evidence rejected', unrelated.ok === false, unrelated)
  check('rejection explains the missing anchors', String(unrelated.reason).includes('/api/user'), unrelated.reason)
  check('claim untouched after rejection', store.get(c.id)?.evidence.length === 0, store.get(c.id)?.evidence)

  const strong = store.attach(c.id, {
    ref: 'task:real',
    pathKey: 'task:real',
    executed: 'curl -X PUT https://t/api/user -d role=admin', executedTrusted: true,
  })
  check('matching evidence accepted', strong.ok === true, strong)
  check('status advanced via verified path', store.get(c.id)?.status === 'partial', store.get(c.id)?.status)
  check('relevance recorded on evidence', store.get(c.id)?.evidence[0]?.relevance?.strength === 'strong', store.get(c.id)?.evidence[0])

  // weak 证据（仅声明覆盖）也接受，但强度标记不同
  const weak = store.attach(c.id, {
    ref: 'task:weak',
    pathKey: 'role:other-user',
    // 故意不标 trusted：这条测的是「仅声明覆盖」只能算 weak
    executed: '/opt/scan.sh',
    artifact: 'PUT /api/user -> 200',
  })
  check('artifact-only evidence accepted as weak', weak.ok === true, weak)
  check('weak strength recorded', store.get(c.id)?.evidence[1]?.relevance?.strength === 'weak', store.get(c.id)?.evidence[1])

  // 自述绕过必须失败（模型端到端发现的漏洞）
  const narrated = store.attach(c.id, {
    ref: 'task:narrated',
    pathKey: 'task:narrated',
    executed: 'node -e "console.log(7)"', executedTrusted: true,
  })
  check('unrelated execution rejected even with a matching claim', narrated.ok === false, narrated)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
