/**
 * 阶段 B 验收：跨进程调度队列。
 *
 * 覆盖：执行与证据落盘、幂等、超时终止（含孙进程）、崩溃恢复、并发上限。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { QueueRunner } from '../dist/queue-runner.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function tmpRoot(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `dsh-secops-${name}-`))
}

// ── 1. 基本执行 + 证据落盘
{
  const root = tmpRoot('basic')
  const runner = new QueueRunner({ queueFile: path.join(root, 'q.jsonl'), evidenceRoot: path.join(root, 'ev'), concurrency: 2 })
  runner.start()
  const task = runner.submit({ kind: 'echo', argv: [process.execPath, '-e', 'console.log("hello-queue")'] })
  await runner.drain()
  const done = runner.get(task.id)
  check('task finished', done?.status === 'done', done)
  check('exit code 0', done?.exitCode === 0, done?.exitCode)
  const stdout = fs.readFileSync(path.join(done.evidenceDir, 'stdout.log'), 'utf8')
  check('stdout captured', stdout.includes('hello-queue'), stdout.slice(0, 80))
  const meta = JSON.parse(fs.readFileSync(path.join(done.evidenceDir, 'meta.json'), 'utf8'))
  check('meta.json has duration', typeof meta.durationMs === 'number' && meta.durationMs >= 0, meta)
  runner.close()
}

// ── 2. 幂等：同 id 重复提交
{
  const root = tmpRoot('idem')
  const runner = new QueueRunner({ queueFile: path.join(root, 'q.jsonl'), evidenceRoot: path.join(root, 'ev') })
  runner.start()
  const a = runner.submit({ id: 'fixed-1', kind: 'echo', argv: [process.execPath, '-e', 'process.exit(0)'] })
  const b = runner.submit({ id: 'fixed-1', kind: 'echo', argv: [process.execPath, '-e', 'process.exit(0)'] })
  check('same id returns same task', a.id === b.id && a.createdAt === b.createdAt)
  check('queue holds one task', runner.list().length === 1, runner.list().map((t) => t.id))
  await runner.drain()
  runner.close()
}

// ── 3. 超时终止，且孙进程同组被杀
{
  const root = tmpRoot('timeout')
  const childPidFile = path.join(root, 'child.pid')
  const runner = new QueueRunner({
    queueFile: path.join(root, 'q.jsonl'),
    evidenceRoot: path.join(root, 'ev'),
    defaultTimeoutMs: 700,
  })
  runner.start()
  const task = runner.submit({
    kind: 'hang',
    argv: ['/bin/sh', '-c', `sleep 30 & echo $! > ${childPidFile}; wait`],
    timeoutMs: 700,
  })
  await runner.drain()
  const done = runner.get(task.id)
  check('timed-out task marked failed', done?.status === 'failed', done?.status)
  check('timeout noted in meta', JSON.parse(fs.readFileSync(path.join(done.evidenceDir, 'meta.json'), 'utf8')).timedOut === true)

  await sleep(600)
  const grandchild = Number(fs.readFileSync(childPidFile, 'utf8').trim())
  let alive = true
  try {
    process.kill(grandchild, 0)
  } catch {
    alive = false
  }
  check('grandchild in process group killed', alive === false, { grandchild, alive })
  runner.close()
}

// ── 4. 崩溃恢复：遗留 running → interrupted
{
  const root = tmpRoot('recover')
  const queueFile = path.join(root, 'q.jsonl')
  const runner1 = new QueueRunner({ queueFile, evidenceRoot: path.join(root, 'ev') })
  runner1.start()
  // 手工制造一条 running 记录（模拟上个进程在任务执行中被杀）
  const store = runner1 // 通过 runner 的公开面写入不现实，直接写文件
  const recs = [
    { t: 'submit', task: { id: 'stale-1', kind: 'x', argv: ['/bin/true'], cwd: root, timeoutMs: 1000, createdAt: Date.now() } },
    { t: 'start', id: 'stale-1', at: Date.now(), attempt: 1 },
  ]
  fs.writeFileSync(queueFile, recs.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8')
  void store
  runner1.close()

  const runner2 = new QueueRunner({ queueFile, evidenceRoot: path.join(root, 'ev') })
  const out = runner2.start()
  check('recovered stale task reported', out.recovered.length === 1 && out.recovered[0] === 'stale-1', out)
  check('stale task downgraded to interrupted', runner2.get('stale-1')?.status === 'interrupted', runner2.get('stale-1'))
  runner2.close()
}

// ── 5. 并发上限
{
  const root = tmpRoot('conc')
  const runner = new QueueRunner({ queueFile: path.join(root, 'q.jsonl'), evidenceRoot: path.join(root, 'ev'), concurrency: 2 })
  runner.start()
  for (let i = 0; i < 5; i++) {
    runner.submit({ id: `c-${i}`, kind: 'sleep', argv: [process.execPath, '-e', 'setTimeout(()=>{},300)'] })
  }
  await sleep(120)
  const running = runner.list().filter((t) => t.status === 'running').length
  check('never more than 2 running', running <= 2, running)
  await runner.drain()
  const doneCount = runner.list().filter((t) => t.status === 'done').length
  check('all 5 completed', doneCount === 5, doneCount)
  runner.close()
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
