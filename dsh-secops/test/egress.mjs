/**
 * 阶段 D 验收：网络出口。
 *
 * 要证明四件事：
 *   1. netns 断掉一切直连（不经过代理就不出去）
 *   2. 代理按 allowlist 放行
 *   3. 代理拒绝越界目标
 *   4. 代理失败时 fail closed（不因代理挂掉而放行）
 *
 * 网络可达性用 http://127.0.0.1:<本地测试服务> 模拟，避免依赖外网稳定性。
 */

import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EgressProxy } from '../dist/egress.js'
import { netnsAvailable, netnsCommand } from '../dist/netns.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}
const run = (argv, timeoutMs = 20_000) =>
  new Promise((resolve) => {
    import('node:child_process').then(({ spawn }) => {
      const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] })
      let out = ''
      let err = ''
      child.stdout.on('data', (b) => (out += String(b)))
      child.stderr.on('data', (b) => (err += String(b)))
      const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
      child.on('close', (code) => {
        clearTimeout(timer)
        resolve({ code, out, err })
      })
    })
  })

check('netns prerequisites present', netnsAvailable() === true)

// 一个本地"上游"服务，代表真实目标
const upstream = http.createServer((req, res) => res.writeHead(200).end('UPSTREAM-OK'))
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
const upstreamPort = upstream.address().port

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-egress-'))
const socketPath = path.join(root, 'egress.sock')
const decisions = []
const proxy = new EgressProxy({
  allowedHosts: ['127.0.0.1'],
  socketPath,
  onDecision: (d) => decisions.push(d),
})
await proxy.start()
check('proxy socket exists', fs.existsSync(socketPath))

// ── 1. 直连被 netns 断掉（不给代理）
{
  const wrapped = netnsCommand({
    argv: ['curl', '-sS', '-m', '4', '-o', '/dev/null', '-w', '%{http_code}', `http://127.0.0.1:${upstreamPort}/`],
    workdir: root,
    proxySocket: socketPath,
    extraEnv: { NO_PROXY: '*', no_proxy: '*' },
  })
  const r = await run(wrapped)
  // netns 内 127.0.0.1 是自己的 loopback，上游服务在宿主 netns，因此不可达
  check('netns isolates loopback (upstream unreachable)', r.out.trim() === '000' || r.code !== 0, { out: r.out, code: r.code })
}

// ── 2. 经过代理，允许目标可达
{
  const wrapped = netnsCommand({
    // --noproxy '' 强制走代理：默认 NO_PROXY 含 127.0.0.1，会绕过代理直连。
    argv: ['curl', '-sS', '-m', '6', '--noproxy', '', `http://127.0.0.1:${upstreamPort}/`],
    workdir: root,
    proxySocket: socketPath,
  })
  const r = await run(wrapped)
  check('allowed host reachable via proxy', r.out.includes('UPSTREAM-OK'), { out: r.out.slice(0, 120), err: r.err.slice(0, 200) })
  check('proxy recorded an allow decision', decisions.some((d) => d.allowed === true), decisions.slice(-3))
}

// ── 3. 越界目标被代理拒绝
{
  decisions.length = 0
  const wrapped = netnsCommand({
    argv: ['curl', '-sS', '-m', '6', '--noproxy', '', '-o', '/dev/null', '-w', '%{http_code}', 'http://10.255.255.1/'],
    workdir: root,
    proxySocket: socketPath,
  })
  const r = await run(wrapped)
  check('out-of-scope denied', !r.out.includes('200'), { out: r.out, err: r.err.slice(0, 160) })
  check('proxy recorded a deny decision', decisions.some((d) => d.allowed === false), decisions.slice(-3))
}

// ── 4. 代理关闭后 fail closed（不自动放行）
{
  await proxy.stop()
  const wrapped = netnsCommand({
    argv: ['curl', '-sS', '-m', '4', '--noproxy', '', '-o', '/dev/null', '-w', '%{http_code}', `http://127.0.0.1:${upstreamPort}/`],
    workdir: root,
    proxySocket: socketPath,
  })
  const r = await run(wrapped)
  check('proxy down => no egress (fail closed)', r.out.trim() !== '200', { out: r.out, code: r.code })
}

// ── 5. 隔离只作用于被包裹的进程，宿主（DSH 自身）出站不受影响
{
  // 外网偶有抖动，最多试 3 次；只用来证明宿主未被 netns 影响。
  let ok = false
  for (let i = 0; i < 3 && !ok; i++) {
    const hostProbe = await run(['curl', '-sS', '-m', '8', '-o', '/dev/null', '-w', '%{http_code}', 'https://registry.npmjs.org'])
    ok = hostProbe.out.trim() === '200'
  }
  check('host egress unaffected (DSH model traffic path)', ok, 'three attempts failed')
}

upstream.close()
const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
