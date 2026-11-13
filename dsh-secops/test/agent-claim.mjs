/**
 * 方向级派活 → 证据链闭环验收。
 *
 * 这一步才是「工程上解决质量」的落点：agent 跑出报告不等于有证据。
 * 产物必须经同一个 archiver 走相关性校验和独立路径判定，
 * 否则调度层只是个更花哨的日志器。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { AgentRegistry } from '../dist/agent-registry.js'
import { DirectionalDispatcher } from '../dist/agent-dispatch.js'
import { createQueueAttempt } from '../dist/agent-tools.js'
import { QueueRunner } from '../dist/queue-runner.js'
import { ClaimStore } from '../dist/provenance-tools.js'
import { createEvidenceArchiver } from '../dist/queue-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-claim-'))
const evidenceRoot = path.join(root, 'evidence')
fs.mkdirSync(evidenceRoot, { recursive: true })

const store = new ClaimStore(undefined, { strictRelevance: false })
const archiver = createEvidenceArchiver(store)

const runner = new QueueRunner({
  queueFile: path.join(root, 'queue.jsonl'),
  evidenceRoot,
  concurrency: 1,
  defaultTimeoutMs: 60_000,
  onFinish: archiver.onFinish,
})
runner.start()

const registry = new AgentRegistry([
  {
    id: 'rabin2',
    direction: 'binary-reverse',
    kind: 'cli',
    command: ['rabin2'],
    capability: 'ELF header inspection',
    priority: 10,
    invocation: (target) => ['-Ij', target],
    verdict: (ctx) => {
      try {
        const doc = JSON.parse(ctx.stdout.trim())
        return { found: doc?.info?.nx === false, detail: `arch=${String(doc?.info?.arch)}` }
      } catch {
        return undefined
      }
    },
  },
])

const dispatcher = new DirectionalDispatcher({
  registry,
  evidenceRoot,
  attempt: createQueueAttempt(runner, { cwd: root, link: archiver.options.link }),
})

// ── 1. 不声明 claim：产物只是日志，不进证据
{
  const out = await dispatcher.dispatch({ direction: 'binary-reverse', target: '/usr/bin/ls' }, new AbortController().signal)
  check('dispatch still settles without a claim', out.settled === true)
  check('no claim linkage means nothing pending', archiver.pendingCount() === 0, archiver.pendingCount())
  check('outcome is unknown without a claim', archiver.outcomeOf(out.attempts[0].evidenceDir.split('/').pop()) === undefined)
}

// ── 2. 声明 claim：产物经相关性校验后成为证据
{
  const claim = store.assert('/usr/bin/ls 的 ELF 头显示启用了 NX 保护')
  const out = await dispatcher.dispatch(
    { direction: 'binary-reverse', target: '/usr/bin/ls', claimId: claim.id },
    new AbortController().signal,
  )
  check('dispatch settles with claim', out.settled === true, out)
  await runner.drain()
  const outcome = archiver.outcomeOf(out.attempts[0].evidenceDir.split('/').pop())
  check('task was linked to the claim', outcome !== undefined, outcome)
  check('task ended up archived as evidence', outcome?.archived === true, outcome)

  const after = store.get(claim.id)
  const evidence = after?.evidence ?? []
  check('claim gained evidence from the dispatch', evidence.length >= 1, evidence.length)
  check('evidence carries a worker source', evidence.some((e) => e?.source?.kind === 'worker'), evidence)
}

// ── 3. 降级链里每个尝试都被记录，只有终态那条带 found
{
  const reg = new AgentRegistry([
    {
      id: 'broken',
      direction: 'binary-reverse',
      kind: 'cli',
      command: ['definitely-missing-binary-abc'],
      capability: 'missing on purpose',
      priority: 1,
      invocation: () => ['x'],
    },
    ...registry.all(),
  ])
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot,
    attempt: createQueueAttempt(runner, { cwd: root, link: archiver.options.link }),
  })
  const claim = store.assert('/usr/bin/ls 是 ELF 文件')
  const out = await d.dispatch(
    { direction: 'binary-reverse', target: '/usr/bin/ls', claimId: claim.id },
    new AbortController().signal,
  )
  check('fallback chain still settles', out.settled === true)
  check('broken agent recorded first', out.attempts[0]?.agentId === 'broken' && out.attempts[0]?.result === 'agent-failure', out.attempts[0])
  check('second agent produced the verdict', out.by === 'rabin2', out.by)
}

runner.close()
await runner.drain()
fs.rmSync(root, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
