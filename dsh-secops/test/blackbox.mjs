/**
 * 纯黑盒探测验收 —— 对着本地靶机跑，靶机里每一处缺陷都是已知答案。
 *
 * 这是这套东西唯一能自证的方式：自造靶机、知道漏洞在哪、什么形态，
 * 然后看探测器抓到的是真信号，还是在对噪声编故事。
 *
 * 靶机埋的六处（engine/blackbox/target.py）：
 *   BOLA / 参数污染 / 栈泄露 / 竞态 / 状态机跳步 / 诱饵迷宫
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn, execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d).slice(0, 300)}`)
}

const ENGINE = '/root/异构agent/engine'
const PORT = 8111
const BASE = `http://127.0.0.1:${PORT}`

const cli = async (args, timeout = 240_000) => {
  try {
    const { stdout } = await execFileAsync('python3', ['-m', 'blackbox.cli', ...args], {
      maxBuffer: 32 * 1024 * 1024, timeout, cwd: ENGINE,
    })
    return JSON.parse(stdout.trim().split('\n').pop() ?? '{}')
  } catch (err) {
    const e = err
    if (typeof e.stdout === 'string' && e.stdout.trim() !== '') {
      try { return JSON.parse(e.stdout.trim().split('\n').pop() ?? '{}') } catch { /* fallthrough */ }
    }
    return { error: String(e.message ?? 'cli failed').slice(0, 300) }
  }
}

const get = async (p, headers = {}) => {
  const r = await fetch(BASE + p, { headers, redirect: 'manual' })
  return { status: r.status, body: await r.text(), cookie: r.headers.get('set-cookie') ?? '' }
}

const login = async (user) => {
  const r = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `user=${user}`,
  })
  const sc = r.headers.get('set-cookie') ?? ''
  const m = sc.match(/sid=([^;]+)/)
  return m ? m[1] : ''
}

// ── 起靶机
const srv = spawn('python3', ['-m', 'blackbox.target', '--port', String(PORT)], {
  cwd: ENGINE, stdio: 'ignore', detached: true,
})
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
await sleep(2200)

let sidA = '', sidB = ''
try {
  const up = await get('/')
  check('靶机已就绪', up.status === 200, up.status)
  sidA = await login('alice')
  sidB = await login('bob')
  check('拿到两个身份', sidA !== '' && sidB !== '', { sidA, sidB })

  const ids = [`alice=cookie:sid=${sidA},role=user`, `bob=cookie:sid=${sidB},role=user`, 'anon=']

  // ── 1. 身份差分抓 BOLA
  {
    const r = await cli(['diff', '--base', BASE, '--path', '/api/invoice/2',
      '--ids', ids[0], '--ids', ids[1], '--ids', ids[2], '--markers', 'bob,9500'])
    const diffs = r.identity?.differences ?? []
    const leaked = diffs.find((d) => d.sensitive?.length > 0)
    check('抓到 BOLA（alice 看到 bob 的标记）', leaked !== undefined, diffs)
    check('给出了硬证据而不只是状态码差异', Array.isArray(leaked?.sensitive) && leaked.sensitive.includes('9500'), leaked)
    const auth = diffs.find((d) => d.dimension?.includes('anon'))
    check('同时识别出认证边界', auth?.status?.includes('401') === true, auth)
  }

  // ── 2. 异常检测抓栈泄露
  {
    const r = await cli(['anomaly', '--base', BASE, '--path', '/api/debug?crash=1', '--samples', '3'])
    const kinds = (r.anomalies ?? []).map((a) => a.kind)
    check('基线采样完成', r.baseline?.settled === true, r.baseline)
    check('抓到栈泄露', kinds.includes('stack-trace'), kinds)
    check('同时抓到路径泄露', kinds.includes('path-leak'), kinds)
  }

  // ── 3. 参数污染（差异在值上）
  {
    const r = await cli(['diff', '--base', BASE, '--path', '/api/search', '--param', 'id', '--ids', 'anon='])
    const variants = r.syntax?.variants ?? []
    check('跑了全部语法变异', variants.length >= 6, variants.length)
    const dup = variants.find((v) => v.variant === 'duplicate-key')
    let used
    try { used = JSON.parse(dup?.body_excerpt ?? '{}').used } catch { used = undefined }
    check('服务端对重复键的解释被记录', used === '1', { used, excerpt: dup?.body_excerpt?.slice(0, 80) })
  }

  // ── 4. 竞态（多轮采样）
  {
    await get('/api/reset')
    const r = await cli(['race', '--base', BASE, '--path', '/api/redeem',
      '--body', 'coupon=WELCOME', '--ids', ids[0], '--method', 'POST',
      '--count', '8', '--reset-url', '/api/reset'], 300_000)
    check('竞态判定为 race-detected', r.verdict === 'race-detected', r.verdict)
    check('给了多轮数据而非单次结论', Array.isArray(r.rounds_data) && r.rounds_data.length >= 3, r.rounds_data?.length)
    const raced = (r.rounds_data ?? []).some((d) => d.successes.concurrent > d.successes.sequential)
    check('确实有一轮并发成功数超过顺序', raced === true, r.rounds_data?.map((d) => d.successes))
  }

  // ── 5. 状态机：跳过登录直接结算
  {
    const steps = JSON.stringify([
      { identity: 'anon', steps: [{ path: '/api/checkout', method: 'GET' }] },
    ])
    const r = await cli(['state', '--base', BASE, '--steps', steps, '--ids', 'anon='])
    check('状态机记录了转移', (r.transitions ?? 0) >= 1, r.transitions)
    const edge = (r.edges ?? [])[0]
    check('记录了从 START 出发的边', edge?.from === 'START', edge)
  }

  // ── 6. 测绘：端点与泄露
  {
    const r = await cli(['map', '--base', BASE, '--paths', '/', '--ids', 'anon='])
    check('测绘出端点', (r.endpoint_count ?? 0) >= 3, r.endpoint_count)
    const paths = (r.endpoints ?? []).map((e) => e.path)
    check('发现了 invoice 与 search 端点', paths.some((p) => p.includes('/api/invoice')) && paths.some((p) => p.includes('/api/search')), paths.slice(0, 6))
  }

  // ── 7. 一键探测（含护栏）
  {
    await get('/api/reset')
    const r = await cli(['probe', '--base', BASE, '--paths', '/,/api/invoice/2,/api/search',
      '--ids', ids[0], '--ids', ids[1], '--markers', 'bob,9500',
      '--race-path', '/api/redeem', '--race-body', 'coupon=WELCOME', '--reset-url', '/api/reset'], 400_000)
    check('一站式跑通三个阶段', r.stages?.map !== undefined && r.stages?.diff !== undefined, Object.keys(r.stages ?? {}))
    const diffs = r.stages?.diff?.differences ?? []
    check('一站式也抓到了跨身份泄露', diffs.some((d) => d.sensitive?.length > 0), diffs.length)
    check('护栏状态被记录', r.guard?.novelty !== undefined, r.guard)
  }

  // ── 8. 范围白名单（fail-closed）
  {
    const r = await cli(['diff', '--base', BASE, '--path', '/api/invoice/2', '--ids', 'anon=', '--host', 'example.invalid'])
    check('白名单外的主机被拒', typeof r.error === 'string' && /scope check failed/.test(r.error), r.error)
  }
} finally {
  try { process.kill(-srv.pid, 'SIGKILL') } catch { try { srv.kill('SIGKILL') } catch { /* ignore */ } }
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
