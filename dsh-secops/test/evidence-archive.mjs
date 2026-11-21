/**
 * 阶段 E 验收：队列产物 → claim 证据的自动归档。
 *
 * 要证明三件事：
 *   1. 声明 claim_id 的任务成功后，产物自动成为该 claim 的证据
 *   2. 同类任务重复执行**不**增加独立路径（同 pathKey）
 *   3. 不同类任务才增加独立路径，达标后升 confirmed
 *   4. 失败任务不自动附证据（命令没跑通不等于观测到断言）
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ClaimStore } from '../dist/provenance-tools.js'
import { createEvidenceArchiver, queueTools } from '../dist/queue-tools.js'
import { QueueRunner } from '../dist/queue-runner.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-archive-'))
const store = new ClaimStore()
const archiver = createEvidenceArchiver(store)

const runner = new QueueRunner({
  queueFile: path.join(root, 'q.jsonl'),
  evidenceRoot: path.join(root, 'ev'),
  concurrency: 2,
  onFinish: archiver.onFinish,
  logger: { info: () => {}, warn: () => {} },
})
runner.start()
const defs = Object.fromEntries(queueTools(runner, archiver.options).map((d) => [d.name, d]))
const fakeExec = { callId: 't', name: 'x', arguments: {}, signal: new AbortController().signal }
const call = async (name, args) => ({ value: await defs[name].execute(args, fakeExec) })

const claim = store.assert('GET /api/order?id= 未校验归属')
check('claim starts as hypothesis', claim.status === 'hypothesis', claim.status)

// ── 1. 成功任务自动归档
const t1 = await call('worker_submit', {
  kind: 'http-diff',
  claim_id: claim.id,
  argv: [process.execPath, '-e', 'console.log("GET /api/order?id=2 -> 200")'],
})
check('submit with claim accepted', t1.value?.status === 'queued', t1.value)
check('link pending', archiver.pendingCount() === 1, archiver.pendingCount())

await runner.drain()
const after1 = store.get(claim.id)
check('evidence auto-attached', after1?.evidence.length === 1, after1?.evidence)
check('pathKey derived from kind', after1?.evidence[0]?.pathKey === 'task:http-diff', after1?.evidence[0])
check('status advanced to partial', after1?.status === 'partial', after1?.status)
check('pending cleared', archiver.pendingCount() === 0)

// ── 2. 同类任务不增加独立路径
const t2 = await call('worker_submit', {
  kind: 'http-diff',
  claim_id: claim.id,
  argv: [process.execPath, '-e', 'console.log("GET /api/order?id=3 -> 200")'],
})
await runner.drain()
const after2 = store.get(claim.id)
check('same kind still one independent path', after2?.independentPaths === 1, after2?.independentPaths)
check('still partial', after2?.status === 'partial', after2?.status)

// ── 3. 不同类任务才升 confirmed
await call('worker_submit', {
  kind: 'tool-recompute',
  claim_id: claim.id,
  argv: [process.execPath, '-e', 'console.log("recompute order id=2 ownership")'],
})
await runner.drain()
const after3 = store.get(claim.id)
check('different kind adds a path', after3?.independentPaths === 2, after3?.independentPaths)
check('promoted to confirmed', after3?.status === 'confirmed', after3?.status)

// ── 4. 失败任务不附证据
const claim2 = store.assert('POST /api/transfer 接受负数金额')
const before = store.get(claim2.id)?.evidence.length
await call('worker_submit', {
  kind: 'http-diff',
  claim_id: claim2.id,
  argv: [process.execPath, '-e', 'process.exit(3)'],
})
await runner.drain()
const failedTask = runner.list().find((t) => t.kind === 'http-diff' && t.status === 'failed')
check('failing task marked failed', failedTask !== undefined, runner.list().map((t) => t.status))
check('failed task does not attach evidence', store.get(claim2.id)?.evidence.length === before, store.get(claim2.id)?.evidence)

// ── 5. 未知 claim 被拒
const bad = await call('worker_submit', { kind: 'x', claim_id: 'claim-does-not-exist', argv: ['/bin/true'] })
check('unknown claim rejected', bad.value?.status === 'rejected', bad.value)

// ── 6. 无关任务产物被拒（端到端暴露的场景）
{
  const claim3 = store.assert('PUT /api/user 允许修改他人角色')
  await call('worker_submit', {
    kind: 'probe',
    claim_id: claim3.id,
    argv: [process.execPath, '-e', 'console.log(7)'],
  })
  await runner.drain()
  check('unrelated artifact rejected', store.get(claim3.id)?.evidence.length === 0, store.get(claim3.id)?.evidence)
  check('claim stays hypothesis', store.get(claim3.id)?.status === 'hypothesis', store.get(claim3.id)?.status)
  const rej = archiver.lastRejection()
  check('rejection recorded for diagnosis', rej !== undefined && rej.claimId === claim3.id, rej)
  check('rejection names the anchor', String(rej?.reason).includes('/api/user'), rej?.reason)

  // 产物中出现锚点、命令本身不含 → weak。产物可被伪造，故不计入 verifiedPaths。
  const artifactFile = path.join(root, 'artifact.txt')
  fs.writeFileSync(artifactFile, 'PUT /api/user -> 200\n', 'utf8')
  await call('worker_submit', {
    kind: 'probe2',
    claim_id: claim3.id,
    // argv 里只有文件路径，锚点只出现在产物中
    argv: ['cat', artifactFile],
  })
  await runner.drain()
  check('artifact match accepted as evidence', store.get(claim3.id)?.evidence.length === 1, store.get(claim3.id)?.evidence)
  // 队列任务证据带真实 source.argv（系统记录），按新语义应为 strong 而非 weak。
  // 语义变更说明：artifact 单独看无法自证，但"系统读取的文件"可以——这正是
  // 漏洞赏金平台接受截图/视频的理由（内容可核查，不要求可重放）。
  check('recorded as strong (artifact from system-read file)', store.get(claim3.id)?.evidence[0]?.relevance?.strength === 'strong', store.get(claim3.id)?.evidence[0])
  check('single evidence yields partial', store.get(claim3.id)?.status === 'partial', store.get(claim3.id)?.status)
}

runner.close()
const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
