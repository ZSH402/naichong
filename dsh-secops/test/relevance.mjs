/**
 * 证据相关性判据的单元测试。
 *
 * 重点覆盖反例：`node -e "console.log(7)"` 这种与断言毫无关系的执行内容
 * 必须被判定为不相关，不能靠 `independentPaths` 蒙混过去。
 */

import { checkEvidenceRelevance, extractAnchors } from '../dist/relevance.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}
const kinds = (anchors) => anchors.map((a) => `${a.kind}:${a.value}`).sort()

// ── 1. 锚点提取
{
  const a = extractAnchors('PUT /api/user 允许修改他人角色')
  check('extracts method+path', kinds(a).includes('method:PUT') && kinds(a).includes('path:/api/user'), a)

  const b = extractAnchors('GET /api/order?id=1 未校验归属')
  check('extracts query param name', kinds(b).includes('param:id'), b)
  check('path excludes query', kinds(b).includes('path:/api/order'), b)

  const c = extractAnchors('访问 https://target.example/api/x 返回 500')
  check('extracts host', kinds(c).includes('host:target.example'), c)
  check('extracts status', kinds(c).includes('status:500'), c)

  const d = extractAnchors('node -e "console.log(7)"')
  check('no anchors in a plain command', d.length === 0, d)

  const e = extractAnchors('时间戳 2026/11/10 的单段数字不应算路径')
  check('filters noisy numeric paths', !kinds(e).some((k) => k.startsWith('path:/2')), e)

  check('empty text yields none', extractAnchors('').length === 0)

  // 幂等
  const t = 'POST /api/transfer 接受负数 amount'
  check('deterministic', JSON.stringify(extractAnchors(t)) === JSON.stringify(extractAnchors(t)))
}

// ── 2. 校验：none —— 这是端到端里被模型点出来的那个场景
{
  const v = checkEvidenceRelevance({
    claim: 'PUT /api/user 允许修改他人角色',
    executed: 'node -e "console.log(7)"',
  })
  check('unrelated command is rejected', v.ok === false, v)
  check('strength none', v.strength === 'none', v.strength)
  check('reason names expected anchors', typeof v.reason === 'string' && v.reason.includes('/api/user'), v.reason)
}

// ── 3. 校验：strong —— 执行内容覆盖锚点
{
  const v = checkEvidenceRelevance({
    claim: 'PUT /api/user 允许修改他人角色',
    executed: 'curl -X PUT https://t/api/user -d role=admin',
  })
  check('matching command accepted', v.ok === true, v)
  check('strength strong', v.strength === 'strong', v.strength)
  check('matched anchors reported', v.matched.length > 0, v.matched)
}

// ── 4. 校验：weak —— 仅产物覆盖
{
  const v = checkEvidenceRelevance({
    claim: 'PUT /api/user 允许修改他人角色',
    executed: '/opt/scan.sh target',
    artifact: 'PUT /api/user -> 200 OK role=admin',
  })
  check('artifact-only evidence accepted as weak', v.ok === true && v.strength === 'weak', v)
  check('weak carries reason', typeof v.reason === 'string' && v.reason.length > 0, v.reason)
}

// ── 4b. 自述不能绕过（端到端里模型用一句自己的话就绕过了旧实现）
{
  const v = checkEvidenceRelevance({
    claim: 'PUT /api/user 允许修改他人角色',
    executed: 'node -e "console.log(7)"',
    // 旧实现里这个字段能单独成立；现在它根本不在判据里
    ...(/** @type {any} */ ({ observed: 'PUT /api/user role change confirmed' })),
  })
  check('self-narration cannot smuggle evidence', v.ok === false, v)
  check('strength none despite narration', v.strength === 'none', v.strength)
}

// ── 5. 断言没有锚点
{
  const strict = checkEvidenceRelevance({ claim: '存在越权问题', executed: 'anything' })
  check('anchorless claim rejected in strict mode', strict.ok === false, strict)
  check('anchorless reason explains why', typeof strict.reason === 'string' && strict.reason.includes('anchor'), strict.reason)

  const loose = checkEvidenceRelevance({ claim: '存在越权问题', executed: 'anything' }, { strict: false })
  check('anchorless claim allowed in non-strict mode', loose.ok === true, loose)
  check('non-strict still marks weak', loose.strength === 'weak', loose.strength)
}

// ── 6. 大小写与规范化
{
  const v = checkEvidenceRelevance({
    claim: 'put /API/User 允许改角色',
    executed: 'curl -X PUT http://x/API/User',
  })
  check('case-insensitive matching', v.ok === true && v.strength === 'strong', v)
}

// ── 7. 部分匹配也算相关（只覆盖 path 不覆盖 method）
{
  const v = checkEvidenceRelevance({
    claim: 'DELETE /api/order 可删除他人订单',
    executed: 'curl http://t/api/order',
  })
  check('any single anchor match is enough', v.ok === true, v)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
