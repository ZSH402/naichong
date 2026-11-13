/**
 * 检测器对照（calibration）验收。
 *
 * 要防的核心失败：检测器坏了却把「没报问题」当成「目标干净」，
 * 以及用「工具这么说」冒充「目标已对照」。
 */
import { DEFAULT_AGENTS, AgentRegistry } from '../dist/agent-registry.js'
import {
  ControlLedger,
  controlGateOf,
  extractProtections,
  judgeControl,
  runAllControls,
} from '../dist/control-check.js'
import { controlRef } from '../dist/control-tools.js'
import { ClaimStore } from '../dist/provenance-tools.js'
import { pathRoles, verificationOf } from '../dist/provenance.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

// ── 1. 输出解析：两种真实格式都要能读
{
  const json = extractProtections('{ "/usr/bin/ls": { "relro":"full","canary":"yes","nx":"yes","pie":"yes" } }')
  check('checksec json flattened', json.get('relro') === 'full' && json.get('canary') === 'yes', [...json])

  const kv = extractProtections('arch     x86\ncanary   true\nnx       true\nbintype  elf')
  check('rabin2 key-value parsed', kv.get('canary') === 'true' && kv.get('nx') === 'true', [...kv])
  check('key-value keeps unrelated fields', kv.get('bintype') === 'elf', [...kv])
}

// ── 2. 判定：clean 才 trusted
{
  const clean = judgeControl('{ "/x": { "relro":"full","canary":"yes","nx":"yes","pie":"yes" } }')
  check('fully hardened sample is clean', clean.clean === true, clean)

  const lazy = judgeControl('{ "/x": { "relro":"partial","canary":"no","nx":"yes","pie":"no" } }')
  check('lazy sample is not clean', lazy.clean === false, lazy)
  check('reason names the failing fields', /canary=no/.test(lazy.reason) && /pie=no/.test(lazy.reason), lazy)
}

// ── 3. 解析不出加固项 ≠ clean（最容易写错的地方）
{
  const noise = judgeControl('scan complete, 0 issues found')
  check('unparsable output is not clean', noise.clean === false, noise)
  check('unparsable reason says why', /解析不到/.test(noise.reason), noise)

  const empty = judgeControl('')
  check('empty output is not clean', empty.clean === false, empty)
}

// ── 4. 缺项不算失败：rabin2 不报 pie/relro 时不能判死
{
  const partial = judgeControl('canary   true\nnx       true')
  check('missing fields do not fail the run', partial.clean === true, partial)
  check('present fields are still reported', /canary=true/.test(partial.observed), partial)
}

// ── 5. 真跑对照（本机实际安装的命令）
{
  const registry = new AgentRegistry(DEFAULT_AGENTS)
  const runs = await runAllControls(registry)
  check('real control runs produced', runs.length >= 2, runs.map((r) => r.agentId))
  const checksec = runs.find((r) => r.agentId === 'checksec')
  check('checksec control trusted on this host', checksec?.verdict === 'trusted', checksec)
  check(
    'control ran the declared argv with $TARGET substituted',
    checksec?.argv[0] === 'checksec' && checksec.argv.some((a) => a.includes('/usr/bin/ls')),
    checksec?.argv,
  )
  check('control output is inspectable', /canary=/.test(checksec?.observed ?? ''), checksec?.observed)

  const unknown = await runAllControls(registry, { only: ['no-such-agent'] })
  check('filtering to unknown agent yields nothing', unknown.length === 0, unknown)
}

// ── 6. 账本
{
  const ledger = new ControlLedger()
  const run = {
    agentId: 'checksec',
    target: '/usr/bin/ls',
    argv: ['checksec'],
    verdict: 'trusted',
    observed: 'canary=yes',
    reason: 'ok',
    exitCode: 0,
    durationMs: 1,
  }
  check('empty ledger trusts nothing', ledger.isTrusted('checksec') === false)
  ledger.record(run)
  check('trusted run recorded', ledger.isTrusted('checksec') === true)
  ledger.record({ ...run, verdict: 'untrusted' })
  check('newer run replaces older', ledger.isTrusted('checksec') === false)
  check('problem list carries the failure', ledger.problems().length === 1, ledger.all())
}

// ── 7. 闸门：四种情况
{
  const ledger = new ControlLedger()
  const gate = controlGateOf(ledger)

  const made = gate('control:checksec@trusted:canary=yes')
  check('no ledger entry is rejected', made.ok === false, made)
  check('rejection tells you to run detector_check', /detector_check/.test(made.reason), made)

  const trusted = {
    agentId: 'checksec',
    target: '/usr/bin/ls',
    argv: ['checksec'],
    verdict: 'trusted',
    observed: 'canary=yes',
    reason: 'ok',
    exitCode: 0,
    durationMs: 1,
  }
  ledger.record(trusted)
  const pass = gate('control:checksec@trusted:canary=yes')
  check('trusted run passes the gate', pass.ok === true, pass)

  const handWritten = gate('looks fine to me')
  check('hand-written ref is rejected', handWritten.ok === false, handWritten)
  check('hand-written rejection explains the risk', /凭空/.test(handWritten.reason), handWritten)

  const lying = gate('control:checksec@untrusted:canary=yes')
  check('ref claiming untrusted is rejected', lying.ok === false, lying)

  ledger.record({ ...trusted, verdict: 'untrusted', observed: 'canary=no', reason: 'sample not hardened' })
  const broken = gate('control:checksec@trusted:canary=yes')
  check('broken detector blocks the gate even if ref says trusted', broken.ok === false, broken)
  check('broken-detector reason quotes the sample', /canary=no/.test(broken.reason), broken)

  const refFor = controlRef({ ...trusted, verdict: 'trusted', observed: 'canary=yes nx=yes' })
  check('controlRef is re-parsable by the gate', /^control:checksec@trusted:/.test(refFor), refFor)
}

// ── 8. ClaimStore：control 证据不能凭空确认断言
{
  const ledger = new ControlLedger()
  const run = {
    agentId: 'checksec',
    target: '/usr/bin/ls',
    argv: ['checksec', '--file=/usr/bin/ls'],
    verdict: 'trusted',
    observed: 'canary=yes nx=yes',
    reason: 'ok',
    exitCode: 0,
    durationMs: 1,
  }
  ledger.record(run)
  const store = new ClaimStore(undefined, { controlGate: controlGateOf(ledger) })
  const claim = store.assert('/opt/target 缺少 stack canary 保护', { falsifier: 'checksec 报 canary=yes' })
  const id = claim.id

  const proof = store.attach(id, {
    ref: '/evidence/checksec-target.txt',
    pathKey: 'tool:checksec',
    executed: 'checksec --file=/opt/target',
    role: 'proof',
  })
  check('proof attached', proof.ok === true, proof)

  const bad = store.attach(id, { ref: 'i-calibrated-it-honestly', pathKey: 'tool:checksec', role: 'control' })
  check('hand-written control ref refused by store', bad.ok === false, bad)

  const good = store.attach(id, { ref: controlRef(run), pathKey: 'tool:checksec', role: 'control' })
  check('detector_check ref accepted', good.ok === true, good)

  const after = store.get(id)
  const roles = pathRoles(after)
  check('control evidence counted as control', roles.control === 1, roles)
  check('control evidence not counted as proof', roles.proof === 1, roles)
  check('control alone cannot confirm a claim', after.status !== 'confirmed', after.status)
}

// ── 9. verificationOf 四态
{
  const replay = { verified: true, at: 1, exitCode: 0, digest: 'd', matchKind: 'strict' }
  const base = {
    id: 'c',
    claim: 'x',
    status: 'partial',
    independentPaths: 1,
    createdAt: 1,
    updatedAt: 1,
    evidence: [],
  }
  const proof = { ref: 'p', pathKey: 'tool:a', role: 'proof', replay, addedAt: 1 }
  const baseline = { ref: 'b', pathKey: 'http:normal', role: 'baseline', replay, addedAt: 1 }
  const control = { ref: 'c', pathKey: 'tool:a', role: 'control', replay, addedAt: 1 }

  check('evidence only → none', verificationOf({ ...base, evidence: [{ ...proof, replay: undefined }] }) === 'none')
  check('strict replay only → reproducible', verificationOf({ ...base, evidence: [proof] }) === 'reproducible')
  check('replay + control → calibrated', verificationOf({ ...base, evidence: [proof, control] }) === 'calibrated')
  check('replay + baseline → cross-checked', verificationOf({ ...base, evidence: [proof, baseline] }) === 'cross-checked')
  check(
    'baseline outranks control',
    verificationOf({ ...base, evidence: [proof, baseline, control] }) === 'cross-checked',
  )
  check('control alone does not verify anything', verificationOf({ ...base, evidence: [control] }) === 'none')
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exit(1)
