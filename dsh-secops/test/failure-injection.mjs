/**
 * 阶段 L 验收：失败注入。
 *
 * 组件测试只覆盖"一切正常"。真实环境会磁盘满、文件损坏、代理挂掉、
 * 输出爆炸。这些路径没测过，就等于没写。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ClaimStore } from '../dist/provenance-tools.js'
import { TaskQueueStore } from '../dist/queue-store.js'
import { replayCommand } from '../dist/replay.js'
import { EgressProxy } from '../dist/egress.js'
import { execFile } from 'node:child_process'
import http from 'node:http'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-fail-'))
const node = process.execPath

// ── 1. 快照写入失败必须可见（磁盘/权限问题不能静默丢证据）
{
  // root 无视目录权限位，必须制造结构性失败：
  // 让 store 的父路径是个普通文件，mkdir/append 必然失败。
  const blocker = path.join(root, 'blocker')
  fs.writeFileSync(blocker, 'not a directory', 'utf8')
  const store = new ClaimStore(undefined, { storePath: path.join(blocker, 'claims.jsonl') })
  store.assert('PUT /api/user 允许修改他人角色')
  const status = store.persistStatus()
  check('persist failure counted', status.failures > 0, status)
  check('persist error captured', typeof status.lastError === 'string' && status.lastError.length > 0, status.lastError)
  check('in-memory state still usable', store.query().length === 1)
}

// ── 2. 队列快照损坏行跳过，不阻断加载
{
  const q = path.join(root, 'corrupt.jsonl')
  const good = { t: 'submit', task: { id: 'ok-1', kind: 'k', argv: ['/bin/true'], cwd: root, timeoutMs: 1000, createdAt: 1 } }
  fs.writeFileSync(q, `${JSON.stringify(good)}\n{"t":"submit","task":{ TRUNCATED\n\n${JSON.stringify({ t: 'start', id: 'ok-1', at: 2, attempt: 1 })}\n`, 'utf8')
  const store = new TaskQueueStore(q)
  const loaded = store.load()
  check('corrupt queue lines skipped', loaded.size === 1, loaded.size)
  check('valid task survives', store.get('ok-1')?.status === 'running', store.get('ok-1')?.status)
}

// ── 3. 队列恢复：进程死后 running 降级 interrupted
{
  const q = path.join(root, 'recover.jsonl')
  const store = new TaskQueueStore(q)
  store.load()
  store.submit({ id: 'r1', kind: 'k', argv: ['/bin/true'], cwd: root, timeoutMs: 1000, createdAt: 1 })
  store.markRunning('r1', 1)
  const reloaded = new TaskQueueStore(q)
  reloaded.load()
  const stale = reloaded.recoverInterrupted()
  check('stale running detected', stale.includes('r1'), stale)
  check('downgraded to interrupted', reloaded.get('r1')?.status === 'interrupted', reloaded.get('r1')?.status)
}

// ── 4. 重放：超时被正确报告，不是无限挂起
{
  const started = Date.now()
  const outcome = await replayCommand({
    argv: [node, '-e', 'setTimeout(()=>{}, 10000)'],
    cwd: root,
    timeoutMs: 300,
  })
  const elapsed = Date.now() - started
  check('timeout is reported', String(outcome.reason).includes('timed out'), outcome.reason)
  check('timeout returns within budget', elapsed < 5000, elapsed)
  // 超时后进程组必须被杀（否则会留下孤儿）
  const survivors = await new Promise((resolve) => {
    // 用 pgrep 精确匹配 node 进程，避免把 ps 自己（命令行里也含该字符串）算进去
    execFile('/usr/bin/pgrep', ['-f', 'node -e setTimeout'], (_e, out) =>
      resolve(String(out ?? '').trim() === '' ? 0 : String(out).trim().split('\n').length),
    )
  })
  check('no orphan process after timeout', survivors === 0, survivors)
}

// ── 5. 代理未启动时 fail closed
{
  const socketPath = path.join(root, 'never-started.sock')
  const proxy = new EgressProxy({ allowedHosts: ['example.com'], socketPath })
  check('proxy not listening', proxy.listening === false)
  // 未 start 的代理不会创建 socket 文件
  check('no socket created', !fs.existsSync(socketPath))
  await proxy.stop() // 停机也不能崩
  check('stop is safe when never started', true)
}

// ── 6. 代理拒绝畸形目标
{
  const socketPath = path.join(root, 'p.sock')
  const proxy = new EgressProxy({ allowedHosts: ['127.0.0.1'], socketPath })
  await proxy.start()
  // 直接用 http 请求打代理，目标畸形
  const status = await new Promise((resolve) => {
    const req = http.request({ socketPath, path: 'http://:bad/', method: 'GET' }, (res) => resolve(res.statusCode))
    req.on('error', () => resolve(-1))
    req.end()
  })
  check('malformed target rejected', status === 400 || status === 403 || status === -1, status)
  await proxy.stop()
}

// ── 7. 输出爆炸被截断
{
  const outcome = await replayCommand({
    argv: [node, '-e', 'process.stdout.write("x".repeat(2000000))'],
    cwd: root,
    maxOutputBytes: 1024,
  })
  check('huge output truncated', outcome.excerpt.length <= 2048, outcome.excerpt.length)
  check('huge output still completes', outcome.exitCode === 0, outcome.exitCode)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
