/**
 * 跨会话 claim 持久化验收。
 *
 * 场景：一次 engagement 会有多轮会话。断线重开后，之前登记过的断言
 * 与证据必须还在，否则「已证伪不再派发」这条规则跨不了会话。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ClaimStore } from '../dist/provenance-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-persist-'))
const storePath = path.join(root, 'claims.jsonl')

// ── 1. 第一次会话：登记 + 加证据
{
  const store = new ClaimStore(undefined, { storePath })
  const c = store.assert('PUT /api/user 允许修改他人角色', { falsifier: '非本人改角色返回 403' })
  store.attach(c.id, {
    ref: 'evidence://req-1',
    pathKey: 'http:differential',
    executed: 'curl -X PUT http://t/api/user -d role=admin', executedTrusted: true,
  })
  check('first session: claim created', store.get(c.id)?.status === 'partial', store.get(c.id)?.status)
  check('snapshot file written', fs.existsSync(storePath) && fs.statSync(storePath).size > 0)
}

// ── 2. 新会话：从文件恢复
{
  const store = new ClaimStore(undefined, { storePath })
  const all = store.query()
  check('second session: claim restored', all.length === 1, all.length)
  const c = all[0]
  check('status preserved', c?.status === 'partial', c?.status)
  check('evidence preserved', c?.evidence.length === 1, c?.evidence)
  check('relevance preserved', c?.evidence[0]?.relevance?.strength === 'strong', c?.evidence[0])
  check('falsifier preserved', typeof c?.falsifier === 'string' && c.falsifier.length > 0, c?.falsifier)

  // 跨会话继续追加：第二条独立路径 → confirmed
  if (c !== undefined) {
    store.attach(c.id, {
      ref: 'evidence://req-2',
      pathKey: 'role:other-user',
      executed: 'curl -X PUT -H Cookie:other http://t/api/user -d role=admin', executedTrusted: true,
    })
    check('cross-session attach promotes to confirmed', store.get(c.id)?.status === 'confirmed', store.get(c.id)?.status)
  }
}

// ── 3. 第三次会话：证伪状态跨会话保持（这是「不重复派发」的前提）
{
  const store = new ClaimStore(undefined, { storePath })
  const c = store.query().find((x) => x.status === 'confirmed')
  check('confirmed survived restart', c !== undefined, store.query().map((x) => x.status))
  if (c !== undefined) {
    store.refute(c.id, { ref: 'evidence://recheck', pathKey: 'http:differential' })
  }
  const store2 = new ClaimStore(undefined, { storePath })
  const refuted = store2.query({ status: 'refuted' })
  check('refuted survived restart', refuted.length === 1, store2.query().map((x) => x.status))
  check('settledIds works across sessions', store2.settledIds().length === 1, store2.settledIds())
}

// ── 4. 无 storePath 时不写文件（默认行为不变）
{
  const mem = new ClaimStore()
  mem.assert('GET /api/x 未校验归属')
  check('memory-only store still works', mem.query().length === 1)
  check('no file written for memory-only', fs.readdirSync(root).filter((f) => f !== 'claims.jsonl').length === 0)
}

// ── 5. 损坏行跳过（append-only 容忍半行）
{
  const badPath = path.join(root, 'bad.jsonl')
  fs.writeFileSync(badPath, '{"id":"claim-ok","claim":"x","status":"hypothesis","evidence":[],"independentPaths":0,"createdAt":1,"updatedAt":1}\n{"broken\n', 'utf8')
  const store = new ClaimStore(undefined, { storePath: badPath })
  check('corrupt line skipped, valid line kept', store.query().length === 1, store.query().length)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
