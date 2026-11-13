/**
 * baseline 角色验收。
 *
 * 一句话：**没有对照的「证明」不算证明**。
 * 两条正常请求不能把一条断言推到 confirmed，这是这套模型存在的全部理由。
 */
import { deriveStatus, pathRoles, withEvidence, newClaim, CONFIRM_THRESHOLD } from '../dist/provenance.js'
import { judgeAnswer } from '../dist/answer-tools.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const ev = (pathKey, role, strength = 'strong') => ({
  ref: `ref-${pathKey}`, pathKey, relevance: { strength, matched: [] }, ...(role === undefined ? {} : { role }), addedAt: 1,
})

const claim = (evidence) => ({ ...newClaim('target allows cross-user read'), evidence, independentPaths: 0 })

// ── 1. baseline 不构成证明路径
{
  const c = claim([ev('k1', 'baseline'), ev('k2', 'baseline')])
  check('two baselines do not confirm', deriveStatus(c.evidence, { mode: 'verified' }) !== 'confirmed',
    deriveStatus(c.evidence, { mode: 'verified' }))
  check('two baselines do not even reach partial', deriveStatus(c.evidence, { mode: 'verified' }) === 'hypothesis',
    deriveStatus(c.evidence, { mode: 'verified' }))
}

// ── 2. 一条证明 + 一条对照 = partial，不是 confirmed
{
  const c = claim([ev('k1', 'proof'), ev('k2', 'baseline')])
  check('one proof plus one baseline is partial', deriveStatus(c.evidence, { mode: 'verified' }) === 'partial',
    deriveStatus(c.evidence, { mode: 'verified' }))
}

// ── 3. 两条独立证明才 confirmed
{
  const c = claim([ev('k1', 'proof'), ev('k2', 'proof')])
  check('two proof paths confirm', deriveStatus(c.evidence, { mode: 'verified' }) === 'confirmed',
    deriveStatus(c.evidence, { mode: 'verified' }))

  const c2 = claim([ev('k1', 'proof'), ev('k2', 'proof'), ev('k3', 'baseline')])
  check('baseline alongside proofs does not break confirmation',
    deriveStatus(c2.evidence, { mode: 'verified' }) === 'confirmed')
}

// ── 4. 缺省 role 视为 proof（向后兼容）
{
  const c = claim([ev('k1', undefined), ev('k2', undefined)])
  check('missing role counts as proof', deriveStatus(c.evidence, { mode: 'verified' }) === 'confirmed',
    deriveStatus(c.evidence, { mode: 'verified' }))
}

// ── 5. pathRoles 分开计数
{
  const c = claim([ev('k1', 'proof'), ev('k2', 'proof'), ev('k3', 'baseline'), ev('k3', 'baseline')])
  const r = pathRoles(c)
  check('proof paths counted separately', r.proof === 2, r)
  check('baseline paths deduped by pathKey', r.baseline === 1, r)
}

// ── 6. replay 模式同样只认 proof
{
  const withReplay = (k, role) => ({ ...ev(k, role), replay: { verified: true, at: 1, exitCode: 0, digest: 'd' } })
  const c = claim([withReplay('k1', 'baseline'), withReplay('k2', 'baseline')])
  check('replay mode also ignores baselines', deriveStatus(c.evidence, { mode: 'replay' }) === 'hypothesis',
    deriveStatus(c.evidence, { mode: 'replay' }))

  const c2 = claim([withReplay('k1', 'proof'), withReplay('k2', 'proof')])
  check('replay mode confirms with two proof paths', deriveStatus(c2.evidence, { mode: 'replay' }) === 'confirmed')
}

// ── 7. withEvidence 保留 role
{
  const base = newClaim('x')
  const next = withEvidence(base, ev('k1', 'baseline'), { mode: 'verified' })
  check('role survives withEvidence', next.evidence[0]?.role === 'baseline', next.evidence[0])
  check('threshold unchanged', CONFIRM_THRESHOLD === 2)
}

// ── 8. 缺对照时提交答案：接受但带警告
{
  const proofOnly = judgeAnswer({ claim: 'x', status: 'confirmed', independentPaths: 2, evidence: [{ role: 'proof' }, { role: 'proof' }] })
  check('proof without baseline is still accepted', proofOnly.accepted === true, proofOnly)
  check('but it carries a baseline warning', proofOnly.warnings.some((w) => /baseline/.test(w)), proofOnly.warnings)
  check('warning is not mixed into missing', proofOnly.missing.length === 0, proofOnly.missing)

  const withBase = judgeAnswer({ claim: 'x', status: 'confirmed', independentPaths: 2, evidence: [{ role: 'proof' }, { role: 'baseline' }] })
  check('baseline present means no baseline warning', !withBase.warnings.some((w) => /baseline/.test(w)), withBase.warnings)
  // 另一类警告（没重跑过）与 baseline 无关，两类必须能分开看
  check('missing replay is reported separately', withBase.warnings.some((w) => /replay/.test(w)), withBase.warnings)
}

// ── 9. 同 ref 不同 role 必须是两条
{
  const base = newClaim('x')
  const one = withEvidence(base, { ...ev('k1', 'proof'), ref: 'same' }, { mode: 'verified' })
  const two = withEvidence(one, { ...ev('k1', 'baseline'), ref: 'same' }, { mode: 'verified' })
  check('same ref+pathKey with a different role is kept', two.evidence.length === 2, two.evidence.length)

  const dup = withEvidence(two, { ...ev('k1', 'baseline'), ref: 'same' }, { mode: 'verified' })
  check('exact duplicate is still dropped', dup.evidence.length === 2, dup.evidence.length)

  const r = pathRoles(two)
  check('roles counted separately for the same pathKey', r.proof === 1 && r.baseline === 1, r)
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
