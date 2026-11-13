/**
 * 阶段 B 集成验收：队列工具在真实 cordis Context + 真实 tools 上的注册与端到端。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import Tools from '@deepseek-ai/dsh-tools'
import SessionStore from '@deepseek-ai/dsh-session'
import Projections from '@deepseek-ai/dsh-session-projection'
import { apply } from '../dist/index.js'
import { QueueRunner } from '../dist/queue-runner.js'
import { queueTools } from '../dist/queue-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-qtools-'))
const ctx = new Context()
ctx.plugin(SystemPrompt)
ctx.plugin(Tools)
ctx.plugin(SessionStore)
ctx.plugin(Projections)
await sleep(500)

await apply(ctx, {
  allowedHosts: ['authorized.example'],
  queue: {
    enabled: true,
    file: path.join(root, 'q.jsonl'),
    evidenceRoot: path.join(root, 'ev'),
    concurrency: 2,
    timeoutMs: 30_000,
  },
})
await sleep(400)

const tools = ctx.get('tools')
const names = tools.schemas().map((s) => s.name)
check('worker_submit registered', names.includes('worker_submit'), names)
check('worker_status registered', names.includes('worker_status'), names)

// 0.2.2 的 tools.execute() 需要可插拔 executor；本测试不构造它，
// 而是直接调用工具定义 —— 注册走真实 ctx.tools，行为走 definition.execute。
const runner = new QueueRunner({
  queueFile: path.join(root, 'q2.jsonl'),
  evidenceRoot: path.join(root, 'ev2'),
  concurrency: 2,
})
runner.start()
const defs = Object.fromEntries(queueTools(runner).map((d) => [d.name, d]))
const fakeExec = { callId: 'test', name: 'x', arguments: {}, signal: new AbortController().signal }
async function call(name, args) {
  const value = await defs[name].execute(args, fakeExec)
  return { isError: false, value }
}

const submitted = await call('worker_submit', {
  kind: 'echo',
  argv: [process.execPath, '-e', 'console.log("via-tool")'],
})
check('submit returned a task', submitted.isError === false, submitted)
const taskId = submitted.value?.id
check('task id present', typeof taskId === 'string', submitted.value)

// 等队列静止
for (let i = 0; i < 100; i++) {
  const st = await call('worker_status', { id: taskId })
  if (st.value?.tasks?.[0]?.status === 'done') break
  await sleep(50)
}

const finalState = await call('worker_status', { id: taskId })
const task = finalState.value?.tasks?.[0]
check('task reached done', task?.status === 'done', task)
check('evidence dir recorded', typeof task?.evidenceDir === 'string', task)
const stdout = fs.readFileSync(path.join(task.evidenceDir, 'stdout.log'), 'utf8')
check('evidence stdout readable', stdout.includes('via-tool'), stdout.slice(0, 60))

const listed = await call('worker_status', { limit: 5 })
check('list returns the task', Array.isArray(listed.value?.tasks) && listed.value.tasks.length >= 1, listed.value)

runner.close()

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
