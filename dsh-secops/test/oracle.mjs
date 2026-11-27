/**
 * 实证预言机 + 补丁变体 + OSV 数据源验收。
 *
 * 三块各自的验收重点：
 *
 *   oracle —— 三态必须分开。**unknown 不是 miss**：超时、OOM、没沙箱都只是
 *             "没测成"，把它们读成"漏洞不存在"就是拿环境故障冒充阴性结论。
 *
 *   patch  —— 走系统 `diff -u`，不是自己写的行集合差。补丁分析要看"这一行
 *             被加在哪里"，集合差会把移动过的行当成没变。
 *
 *   OSV    —— `fixed` 事件直接给出修复版本，不需要从 endExcluding 反推。
 *             用真实 osv.dev 数据验（lodash / requests / express）。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ClaimStore } from '../dist/provenance-tools.js'
import { oracleTools } from '../dist/oracle-tools.js'
import { patchTools } from '../dist/patch-tools.js'
import { CveStore } from '../dist/cve-store.js'
import { findRunner } from '../dist/oracle.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

const runner = findRunner()
console.log(`沙箱执行器: ${runner ?? '未找到（oracle 用例会整体跳过）'}\n`)

// ── 1. 实证预言机
if (runner !== null) {
  const store = new ClaimStore()
  const oracle = oracleTools(store)[0]

  // 1a. hit：canary 出现在输出里
  {
    const c = store.assert('GET /probe/canary 会回显服务端随机串')
    const out = await oracle.execute({
      claim_id: c.id,
      argv: ['sh', '-c', 'echo "GET /probe/canary -> token=CNRY-7f3a91"'],
      expect: { type: 'canary', token: 'CNRY-7f3a91' },
      timeout_sec: 20,
      mem: '128M',
      note: 'canary probe',
    }, {})
    check('canary 命中判为 hit', out.outcome === 'hit', { o: out.outcome, r: out.reason })
    check('hit 推进了断言状态', store.get(c.id)?.status !== 'hypothesis', store.get(c.id)?.status)
    check('证据来自系统执行的 argv', store.get(c.id)?.evidence[0]?.relevance?.strength === 'strong', store.get(c.id)?.evidence[0]?.relevance)
    check('沙箱确实走了 supervisor', out.supervised === true, out.supervised)
  }

  // 1b. miss：命令跑通但期望不满足
  {
    const c = store.assert('GET /probe/canary 会回显服务端随机串（负例）')
    const before = store.get(c.id).status
    const out = await oracle.execute({
      claim_id: c.id,
      argv: ['sh', '-c', 'echo "GET /probe/canary -> token=WRONG"'],
      expect: { type: 'canary', token: 'CNRY-7f3a91' },
      timeout_sec: 20,
      mem: '128M',
    }, {})
    check('期望不满足判为 miss', out.outcome === 'miss', { o: out.outcome, r: out.reason })
    check('miss 不自动判死（只是 advisory）', store.get(c.id)?.status === before, { before, after: store.get(c.id)?.status })
    check('miss 入库的角色是 refutation', store.get(c.id)?.evidence[0]?.role === 'refutation', store.get(c.id)?.evidence[0]?.role)
    check('miss 的反驳是非决定性的', store.get(c.id)?.evidence[0]?.refutation?.kind === 'advisory', store.get(c.id)?.evidence[0]?.refutation)
  }

  // 1c. unknown：超时不能算 miss
  {
    const c = store.assert('这个目标会响应慢查询（超时用例）')
    const before = store.get(c.id).status
    const out = await oracle.execute({
      claim_id: c.id,
      argv: ['sh', '-c', 'sleep 30; echo done'],
      expect: { type: 'output-contains', text: 'done' },
      timeout_sec: 2,
      mem: '128M',
    }, {})
    check('超时判为 unknown', out.outcome === 'unknown', { o: out.outcome, r: out.reason })
    check('unknown 不入库', store.get(c.id)?.evidence.length === 0, store.get(c.id)?.evidence.length)
    check('unknown 不改变状态', store.get(c.id)?.status === before, store.get(c.id)?.status)
  }

  // 1d. OOM 也是 unknown，不是 miss
  {
    const c = store.assert('内存暴涨用例')
    const out = await oracle.execute({
      claim_id: c.id,
      argv: ['python3', '-c', 'b=[]\nfor i in range(400): b.append(bytearray(1024*1024))'],
      expect: { type: 'exit-code', exact: 0 },
      timeout_sec: 30,
      mem: '64M',
    }, {})
    check('OOM 判为 unknown 而非 miss', out.outcome === 'unknown' && out.oom_kill > 0, { o: out.outcome, oom: out.oom_kill })
  }

  // 1e. 没声明期望就拒绝跑
  {
    const c = store.assert('随便一条断言')
    const out = await oracle.execute({ claim_id: c.id, argv: ['true'], expect: {} }, {})
    check('未声明成功条件时拒绝执行', out.outcome === 'unknown' && /declare what counts as success/.test(out.reason), out.reason)
  }
}

// ── 2. 补丁变体
{
  const patcher = patchTools()[0]
  const before = `function handler(req, res) {
  const name = req.query.name
  const r = lookup(name)
  res.send(r.description)
}
`
  const after = `function handler(req, res) {
  const name = req.query.name
  if (name == null) { return res.status(400).send('missing') }
  const r = lookup(name)
  res.send(r.description)
}
`
  const out = await patcher.execute({ before_text: before, after_text: after }, {})
  check('识别出空值检查', out.found === true && out.kind === 'null-guard', { k: out.kind })
  check('提取到危险汇点信号', Array.isArray(out.signals) && out.signals.includes('lookup'), out.signals)
  check('生成了可跑的 semgrep 骨架', typeof out.semgrep_rule === 'string' && out.semgrep_rule.includes('rules:'), (out.semgrep_rule || '').slice(0, 60))
  check('新增行里没有混入未变的行', !out.added_lines.includes('const name = req.query.name'), out.added_lines)

  const flipped = await patcher.execute({ before_text: before, after_text: before }, {})
  check('两版相同时如实报告', flipped.found === false, flipped)

  const auth = await patcher.execute({
    before_text: `app.post('/admin/config', (req, res) => { res.json({}) })`,
    after_text: `app.post('/admin/config', requireAuth, requireRole('admin'), (req, res) => { res.json({}) })`,
  }, {})
  check('识别出授权检查', auth.found === true && auth.kind === 'auth-guard', { k: auth.kind })
}

// ── 3. OSV 数据源
{
  const f = '/tmp/osv_merged.json'
  if (!fs.existsSync(f)) {
    console.log('SKIP  /tmp/osv_merged.json 不存在')
  } else {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-osv-'))
    const store = new CveStore({ path: path.join(dir, 'idx.jsonl') })
    const r = store.importOsv(JSON.parse(fs.readFileSync(f, 'utf8')))
    check(`导入真实 OSV ${r.imported} 条`, r.imported >= 20, r)

    const old = store.query({ product: 'lodash', version: '4.17.20', limit: 50 })
    check('lodash 4.17.20 命中漏洞', old.length > 0, old.length)
    const withFix = old.find((h) => h.fixAt !== undefined)
    check('OSV 的 fixed 直接给出修复版本', withFix !== undefined, old.map((h) => h.fixAt))

    const fixed = store.query({ product: 'lodash', version: '4.17.21', limit: 50 })
    check('lodash 4.17.21 不再命中已修复的那批', fixed.length < old.length, { old: old.length, fixed: fixed.length })

    const req22 = store.query({ product: 'requests', version: '2.19.0', limit: 50 })
    check('PyPI 生态也能查（requests 2.19.0）', req22.length > 0, req22.length)
  }
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
