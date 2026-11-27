/**
 * 感知层 / 搜索层验收：调用图、路由簇、假设排序、sanitizer 判定。
 *
 * 这四项的共同点：它们都是**把模型不该靠直觉回答的问题变成计算**。
 * 所以验收也围绕这一点——图要能回答"有没有调用方"，簇要能分辨
 * "同一簇里谁漏了守卫"，排序要能给出理由，sanitizer 要能区分
 * "报告了问题"和"根本没编译进去"。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { ClaimStore } from '../dist/provenance-tools.js'
import { searchTools } from '../dist/search-tools.js'
import { judge } from '../dist/oracle.js'

const execFileAsync = promisify(execFile)
const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

const SCRIPT = '/root/异构agent/engine/nav/callgraph.py'

// ── fixture：一个带调用关系与路由守卫的小仓库
const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-nav-'))
fs.mkdirSync(path.join(repo, 'src'), { recursive: true })
fs.writeFileSync(path.join(repo, 'src', 'app.js'), `
const express = require('express')
const app = express()

app.post('/api/admin/config', requireAuth, requireRole('admin'), (req, res) => { saveConfig(req.body); res.json({}) })
app.post('/api/admin/role',   requireAuth, requireRole('admin'), (req, res) => { saveRole(req.body);   res.json({}) })
app.post('/api/user/export', (req, res) => { dumpAll(req.query.user_id); res.json({}) })

function saveConfig(body) { return body }
function saveRole(body)   { return body }
function dumpAll(id)      { return id }
function unusedHelper(x)  { return x }
`)
fs.writeFileSync(path.join(repo, 'src', 'dead.py'), `
def orphan_func(value):
    return value * 2

def caller():
    return helper()
`)

const runPy = async (args) => {
  const { stdout } = await execFileAsync('python3', [SCRIPT, ...args], { maxBuffer: 8 * 1024 * 1024, timeout: 120_000 })
  return JSON.parse(stdout.trim().split('\n').pop())
}

// ── 1. 调用图
{
  const stats = await runPy(['build', repo])
  check('建图统计出函数与边', stats.functions >= 6 && stats.call_edges >= 3, stats)
  check('识别了两种语言', stats.files >= 2, stats.files)

  const reach = await runPy(['callers', repo, 'saveConfig'])
  check('有调用方的函数被正确识别', reach.caller_count >= 1, reach)

  const dead = await runPy(['callers', repo, 'unusedHelper'])
  check('无调用方的函数报为不可达', dead.caller_count === 0 && /unreachable/.test(dead.note), dead)

  // 跨语言：Python 侧的孤儿函数
  const dead2 = await runPy(['callers', repo, 'orphan_func'])
  check('Python 里的孤儿函数也识别出来', dead2.caller_count === 0, dead2)

  const slice = await runPy(['slice', repo, 'dumpAll', '--hops', '1'])
  check('切片返回中心节点的邻域', slice.nodes.some((n) => n.symbol === 'dumpAll') && slice.nodes.length >= 1, slice.nodes.map((n) => n.symbol))
}

// ── 2. 路由簇与守卫覆盖
{
  const routes = await runPy(['routes', repo])
  const admin = routes.clusters.find((c) => c.prefix === '/api/admin')
  const user = routes.clusters.find((c) => c.prefix === '/api/user')
  check('admin 簇两条都有守卫', admin?.guarded === 2 && admin.unguarded.length === 0, admin)
  check('user 簇没有对照时不乱报', user !== undefined && user.suspicious.length === 0, user)
  check('总路由数正确', routes.total_routes >= 3, routes.total_routes)
}

// ── 3. 假设排序
{
  const store = new ClaimStore()
  const a = store.assert('POST /api/user/export 未校验租户归属')
  const b = store.assert('POST /api/admin/config 缺少 RBAC')
  // 给 b 一条强证据：它变成 partial（仍未定论），但均值高于 a
  for (const i of [1]) {
    store.attach(b.id, {
      ref: `e${i}`, pathKey: `p${i}`,
      executed: 'curl -X POST http://t/api/admin/config -d role=admin',
      executedTrusted: true,
    })
  }

  const next = searchTools(store)[0]
  const out = await next.execute({ limit: 5 }, {})
  check('返回所有未定论假设', out.considered === 2, out.considered)
  check('每条都带排序理由', out.picks.every((p) => typeof p.reason === 'string' && p.reason.length > 0), out.picks)
  check('每条都有分数与尝试次数', out.picks.every((p) => typeof p.score === 'number' && typeof p.attempts === 'number'), out.picks)
  // b 已缴 2 次且 yield 高，a 一次没试——UCB 的探索项应该让 a 排上来
  check('未试过的假设被优先考虑', out.picks[0].claim_id === a.id, out.picks.map((p) => [p.claim_id === a.id ? 'a' : 'b', p.score]))
}

// ── 4. sanitizer 判定
{
  const base = { exit: 0, signal: 0, elapsed_ms: 10, peak_mem_kb: 100, timed_out: false, kill_reason: '', killed: 0, oom_kill: 0, supervised: true, note: '', log_path: '', argv: [] }
  check('ASan 报告判为 hit', judge(base, { type: 'sanitizer' }, 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1').outcome === 'hit')
  check('无 sanitizer 输出判为 unknown（不是 miss）', judge(base, { type: 'sanitizer' }, 'hello world').outcome === 'unknown')
  check('有 sanitizer 但类型不符判为 miss', judge(base, { type: 'sanitizer', kind: 'thread' }, 'ERROR: AddressSanitizer: heap-buffer-overflow').outcome === 'miss')
  check('UBSan 类型能识别', judge(base, { type: 'sanitizer', kind: 'undefined' }, 'runtime error: signed integer overflow').outcome === 'hit')
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
