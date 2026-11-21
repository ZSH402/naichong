/**
 * 阶段 J 验收：证据可重放。
 *
 * 要证明：
 *   1. 骨架摘要对易变部分（时间戳/UUID/数字）免疫，对结构变化敏感
 *   2. 可重放且一致的证据 → verified
 *   3. 输出与记录不符的证据 → 不 verified
 *   4. 没有来源的证据无法重放，不能冒充已核实
 *   5. claim 状态由「strong 且 replay verified」驱动
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { replayCommand, skeletonDigest, strictDigest, digestArtifact, digestArtifactStrict } from '../dist/replay.js'
import { ClaimStore } from '../dist/provenance-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-replay-'))
const node = process.execPath

// ── 1. 骨架摘要的稳定性
{
  const a = 'GET /api/user 200 at 2026-11-10T10:00:00Z id=550e8400-e29b-41d4-a716-446655440000 took 12ms'
  const b = 'GET /api/user 200 at 2026-11-10T11:23:45Z id=7c9e6679-7425-40de-944b-e07fc1f90ae7 took 987ms'
  check('volatile parts are normalized', skeletonDigest(a) === skeletonDigest(b), { a: skeletonDigest(a), b: skeletonDigest(b) })

  const c = 'GET /api/orders 403'
  check('structural change changes digest', skeletonDigest(a) !== skeletonDigest(c))
  check('empty text is stable', skeletonDigest('') === skeletonDigest(''))
}

// ── 2. 重放成功且一致
{
  const cmd = [node, '-e', 'console.log("PUT /api/user -> 200")']
  const first = await replayCommand({ argv: cmd, cwd: root })
  check('replay runs', first.ran === true, first)
  check('replay exit 0', first.exitCode === 0, first.exitCode)

  const again = await replayCommand({
    argv: cmd,
    cwd: root,
    baselineDigest: first.digest,
    baselineStrictDigest: strictDigest('PUT /api/user -> 200'),
  })
  check('replay reproduces exactly (strict)', again.matchKind === 'strict', { first: first.digest, again: again.digest, kind: again.matchKind })
}

// ── 3. 重放与记录不符
{
  // 状态码变化是语义分水岭，应该判 none（结构都不同）
  const statusDrift = await replayCommand({
    argv: [node, '-e', 'console.log("PUT /api/user -> 500")'],
    cwd: root,
    baselineDigest: skeletonDigest('PUT /api/user -> 200'),
    baselineStrictDigest: strictDigest('PUT /api/user -> 200'),
  })
  check('status code change is a structural mismatch', statusDrift.matchKind === 'none', statusDrift.matchKind)

  // 非状态码的数值漂移（计数）→ 结构相同、数值不同 → structural，不是 strict
  const countDrift = await replayCommand({
    argv: [node, '-e', 'console.log("found 3 items in scan")'],
    cwd: root,
    baselineDigest: skeletonDigest('found 5000 items in scan'),
    baselineStrictDigest: strictDigest('found 5000 items in scan'),
  })
  check('numeric-only drift detected as non-strict', countDrift.matchKind === 'structural', countDrift.matchKind)
  check('numeric drift carries a reason', typeof countDrift.reason === 'string' && countDrift.reason.includes('numeric'), countDrift.reason)

  // 结构都不同 → none
  const far = await replayCommand({
    argv: [node, '-e', 'console.log("UNRELATED")'],
    cwd: root,
    baselineDigest: skeletonDigest('GET /completely/different 404'),
    baselineStrictDigest: strictDigest('GET /completely/different 404'),
  })
  check('structural mismatch detected', far.matchKind === 'none', far.matchKind)

  // 计数变化（5000 vs 3）：旧实现会把它们归一成同一个，现在是 structural 而不是 strict
  const countA = 'found 5000 items'
  const countB = 'found 3 items'
  check('numeric-only change is not strict-equal', strictDigest(countA) !== strictDigest(countB), {
    a: strictDigest(countA),
    b: strictDigest(countB),
  })
  check('numeric-only change is structural-equal', skeletonDigest(countA) === skeletonDigest(countB))
}

// ── 4. 命令失败
{
  const outcome = await replayCommand({ argv: [node, '-e', 'process.exit(3)'], cwd: root })
  check('failing command reports exit code', outcome.exitCode === 3, outcome)
}

// ── 5. ClaimStore.verify 全链路
{
  const artifactOf = (text) => digestArtifact(text, '')
  const store = new ClaimStore()
  const claim = store.assert('PUT /api/user 允许修改他人角色')

  // 证据 A：命令真实触及锚点，产物可复现
  const argvA = [node, '-e', 'console.log("PUT /api/user role=admin -> 200")']
  const probeA = await replayCommand({ argv: argvA, cwd: root })
  store.attach(claim.id, {
    ref: 'task:a',
    pathKey: 'http:differential',
    executed: argvA.join(' '), executedTrusted: true, executedTrusted: true,
    artifact: 'PUT /api/user role=admin -> 200',
    source: { kind: 'worker', taskId: 'a', argv: argvA, cwd: root },
    baselineDigest: artifactOf('PUT /api/user role=admin -> 200'),
    baselineStrictDigest: digestArtifactStrict('PUT /api/user role=admin -> 200', ''),
  })
  check('evidence attached before verify', store.get(claim.id)?.evidence.length === 1, store.get(claim.id)?.evidence)
  check('artifact baseline matches actual run', probeA.matchesBaseline, { digest: probeA.digest })

  const verify1 = await store.verify(claim.id)
  check('verify reports one checked', verify1.checked === 1, verify1)
  check('verify marks it verified', verify1.verified === 1, verify1)
  check('status advances to partial after replay', store.get(claim.id)?.status === 'partial', store.get(claim.id)?.status)
  check('replay outcome persisted on evidence', store.get(claim.id)?.evidence[0]?.replay?.verified === true, store.get(claim.id)?.evidence[0])

  // 第二条独立路径必须换工具（同一可执行文件只算一条）
  const argvB = ['/bin/echo', 'PUT /api/user as other user -> 200']
  store.attach(claim.id, {
    ref: 'task:b',
    pathKey: 'role:other-user',
    executed: argvB.join(' '), executedTrusted: true,
    artifact: 'PUT /api/user as other user -> 200',
    source: { kind: 'worker', taskId: 'b', argv: argvB, cwd: root },
    baselineDigest: artifactOf('PUT /api/user as other user -> 200'),
    baselineStrictDigest: digestArtifactStrict('PUT /api/user as other user -> 200', ''),
  })
  const verify2 = await store.verify(claim.id)
  check('second path verified', verify2.verified === 2, verify2)
  check('two replay-verified paths from DIFFERENT tools promote to confirmed', store.get(claim.id)?.status === 'confirmed', store.get(claim.id)?.status)

  // 反例：同一工具换 pathKey 不能凑数
  const claim2 = store.assert('GET /api/order 未校验归属')
  for (const [ref, pk] of [['t1', 'http:a'], ['t2', 'http:b']]) {
    const a = [node, '-e', `console.log("GET /api/order ${pk} -> 200")`]
    store.attach(claim2.id, {
      ref,
      pathKey: pk,
      executed: a.join(' '), executedTrusted: true,
      artifact: `GET /api/order ${pk} -> 200`,
      source: { kind: 'worker', taskId: ref, argv: a, cwd: root },
      baselineDigest: digestArtifact(`GET /api/order ${pk} -> 200`, ''),
      baselineStrictDigest: digestArtifactStrict(`GET /api/order ${pk} -> 200`, ''),
    })
  }
  await store.verify(claim2.id)
  check('same tool with different pathKey does NOT reach confirmed', store.get(claim2.id)?.status !== 'confirmed', store.get(claim2.id)?.status)
}

// ── 6. 无来源的证据不能重放
{
  const store = new ClaimStore()
  const claim = store.assert('GET /api/order 未校验归属')
  store.attach(claim.id, { ref: 'manual', pathKey: 'human', executed: 'curl http://t/api/order', executedTrusted: true })
  const result = await store.verify(claim.id)
  check('manual evidence is not replayable', result.ok === false && result.checked === 0, result)
  check('reason explains why', String(result.reason).includes('replayable'), result.reason)
  check('manual-only claim stays partial', store.get(claim.id)?.status === 'partial', store.get(claim.id)?.status)
}

// ── 7. 重放失败不会把 claim 推上去
{
  const store = new ClaimStore()
  const claim = store.assert('POST /api/transfer 接受负数金额')
  // executed 必须触及锚点，否则相关性闸先拒，测不到重放这一层
  const argv = [node, '-e', 'console.log("POST /api/transfer -> 200")']
  store.attach(claim.id, {
    ref: 'task:bad',
    pathKey: 'http:differential',
    executed: argv.join(' '), executedTrusted: true,
    artifact: 'POST /api/transfer -> 200',
    source: { kind: 'worker', taskId: 'bad', argv, cwd: root },
    // 故意给一个对不上的基线，模拟「记录被篡改」
    baselineDigest: skeletonDigest('completely different artifact'),
    baselineStrictDigest: strictDigest('completely different artifact'),
  })
  const result = await store.verify(claim.id)
  check('tampered baseline fails verification', result.verified === 0, result)
  check('claim not promoted by failed replay', store.get(claim.id)?.status === 'partial', store.get(claim.id)?.status)
  check('failure reason recorded', store.get(claim.id)?.evidence[0]?.replay?.verified === false, store.get(claim.id)?.evidence[0])
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
