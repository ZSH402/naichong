/**
 * 白盒反驳器验收。
 *
 * 这个文件要证明的核心性质只有一条：**反驳器只杀幻觉，不杀真漏洞。**
 *
 * 所以用例是成对设计的：
 *   - 断言提到的端点在仓库里根本不存在 → 必须判死
 *   - 断言提到的端点存在但确实没有守卫 → **必须不判死**（这多半就是真漏洞）
 *   - 端点存在且有守卫 → 只给 advisory，状态不动
 *   - 模型自己写一段"这不可达"当反驳 → 拿不到 strong，杀不掉任何东西
 *
 * 最后一条是整套机制的底线：能被复核的事实才有否决权。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ClaimStore } from '../dist/provenance-tools.js'
import { refuteTools } from '../dist/refute-tools.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

// ── fixture：一个典型的 Express 应用
const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-refute-repo-'))
fs.mkdirSync(path.join(repo, 'routes'), { recursive: true })
fs.writeFileSync(
  path.join(repo, 'routes', 'admin.js'),
  `const express = require('express')
const router = express.Router()
const { requireAuth, requireRole } = require('../middleware/auth')

// 有守卫：两类检查都挂了
router.post('/api/admin/config', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ ok: true })
})

module.exports = router
`,
)
fs.writeFileSync(
  path.join(repo, 'routes', 'user.js'),
  `const express = require('express')
const router = express.Router()

// 没有守卫：这就是真漏洞的形态，反驳器不该说话
router.post('/api/user/export', (req, res) => {
  const userId = req.query.user_id
  res.json({ data: loadAll(userId) })
})

module.exports = router
`,
)
fs.mkdirSync(path.join(repo, 'middleware'), { recursive: true })
fs.writeFileSync(path.join(repo, 'middleware', 'auth.js'), 'module.exports = { requireAuth: () => {}, requireRole: () => {} }\n')

const store = new ClaimStore()
const tool = refuteTools(store)[0]

// ── 1. 端点根本不存在 → 判死
{
  const c = store.assert('POST /api/billing/refund 未校验租户归属，可越权退款')
  const before = c.status
  const out = await tool.execute({ claim_id: c.id, repo }, {})
  const after = store.get(c.id)
  check('不存在的端点被判死', after.status === 'refuted', { before, after: after.status, v: out.verdict })
  check('判死依据是 anchor-absent', out.findings.some((f) => f.check === 'anchor-absent' && f.kind === 'decisive'), out.findings)
  check('反驳证据已入库', out.evidence_ref !== '' && after.evidence.length === 1, after.evidence.length)
  check('反驳证据角色正确', after.evidence[0].role === 'refutation', after.evidence[0].role)
  check('反驳证据是 strong（系统读的文件）', after.evidence[0].relevance?.strength === 'strong', after.evidence[0].relevance)
}

// ── 2. 端点存在但没有守卫 → 不许判死（这是真漏洞）
{
  const c = store.assert('POST /api/user/export 未校验租户归属，可越权导出他人数据')
  const out = await tool.execute({ claim_id: c.id, repo }, {})
  const after = store.get(c.id)
  check('真漏洞没被反驳掉', after.status !== 'refuted', { after: after.status, v: out.verdict })
  check('没有产出决定性反驳', out.decisive === 0, out.findings)
  check('结论是"未找到矛盾"', /no contradiction/.test(out.verdict), out.verdict)
}

// ── 3. 端点存在且有守卫 → 只给 advisory
{
  const c = store.assert('POST /api/admin/config 未校验管理员角色，普通用户可改配置')
  const out = await tool.execute({ claim_id: c.id, repo }, {})
  const after = store.get(c.id)
  check('有守卫时只给 advisory', out.decisive === 0 && out.advisory > 0, { d: out.decisive, a: out.advisory })
  check('advisory 不改变状态', after.status !== 'refuted', after.status)
  check('报告里指向守卫位置', out.findings.some((f) => f.check === 'guard-found' && typeof f.location === 'string'), out.findings)
}

// ── 4. 底线：模型自述的反驳杀不掉东西
{
  const c = store.assert('POST /api/user/export 的 loadAll 不做租户过滤')
  const before = c.status
  store.attach(c.id, {
    ref: 'model-says',
    pathKey: 'x',
    artifact: '{"check":"symbol-uncalled","detail":"loadAll has no callers"}',
    role: 'refutation',
    refutation: { kind: 'decisive', check: 'symbol-uncalled' },
  })
  const after = store.get(c.id)
  check('模型自述的反驳不算数', after.status === before, { before, after: after.status })
  const rel = after.evidence[0]?.relevance?.strength
  check('模型自述拿不到 strong', rel !== 'strong', rel)
}

// ── 5. 断言没有可搜锚点时明确拒绝，不静默
{
  const c = store.assert('这个系统存在严重的安全问题')
  const out = await tool.execute({ claim_id: c.id, repo }, {})
  check('无锚点断言给出可操作的原因', /no searchable anchors/.test(out.verdict), out.verdict)
}

// ── 6. 仓库路径不存在时不误判
{
  const c = store.assert('POST /api/user/export 越权')
  const out = await tool.execute({ claim_id: c.id, repo: '/nonexistent/path' }, {})
  check('仓库不存在时如实报告', /repo not found/.test(out.verdict) && out.decisive === 0, out.verdict)
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
