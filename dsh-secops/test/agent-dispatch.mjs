/**
 * 方向级 Agent 注册与降级验收。
 *
 * 重点不是「能换下一个」，而是**什么时候不该换**：
 *   - 跑通了但没结论（inconclusive）→ 换，但不把这个 agent 判死
 *   - 工具没装（ENOENT）→ 换，且判死
 *   - promptfoo exit 100 这种「有失败用例」→ 不换，那本身就是结论
 * 判错这三种，系统就会在「反复重试坏工具」和「把有效结论当故障」之间来回摆。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  AgentRegistry,
  DEFAULT_AGENTS,
  corvusVerdict,
  promptfooVerdict,
  rabinVerdict,
  sarifVerdict,
} from '../dist/agent-registry.js'
import {
  DirectionalDispatcher,
  buildArgv,
  classifyProcess,
} from '../dist/agent-dispatch.js'
import { renderDispatch } from '../dist/agent-tools.js'
import { detectTargetShape, fitness } from '../dist/agent-registry.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-agent-'))

const cand = (id, extra = {}) => ({
  id,
  direction: 'mcp-security',
  kind: 'cli',
  capability: `stub ${id}`,
  command: ['true'],
  invocation: (target) => ['scan', target],
  ...extra,
})

// ── 1. 注册表：优先级与健康
{
  const reg = new AgentRegistry([
    cand('low', { priority: 30 }),
    cand('high', { priority: 10 }),
    cand('mid', { priority: 20 }),
  ])
  check('selects by priority', reg.select('mcp-security')?.id === 'high')
  check('available is ordered', reg.available('mcp-security').map((c) => c.id).join(',') === 'high,mid,low')

  reg.reportFailure('high')
  check('single failure does not cool down', reg.list('mcp-security').find((a) => a.id === 'high')?.cooling === false)

  reg.reportFailure('high')
  check('two failures cool down', reg.list('mcp-security').find((a) => a.id === 'high')?.cooling === true)
  check('cooled candidate is skipped', reg.select('mcp-security')?.id === 'mid')

  reg.reportSuccess('high')
  check('success clears cooldown', reg.select('mcp-security')?.id === 'high')

  reg.markUnavailable('high')
  check('unavailable is skipped', reg.select('mcp-security')?.id === 'mid')
  check('unavailable reported in state', reg.list('mcp-security').find((a) => a.id === 'high')?.unavailable === true)
}

// ── 2. 注册表：全不可用
{
  const reg = new AgentRegistry([cand('only')])
  reg.markUnavailable('only')
  check('all unavailable yields undefined', reg.select('mcp-security') === undefined)
  check('unknown direction yields undefined', reg.select('crypto') === undefined)
  check('duplicate id rejected', (() => {
    try {
      new AgentRegistry([cand('dup'), cand('dup')])
      return false
    } catch {
      return true
    }
  })())
}

// ── 3. 冷却按时间恢复
{
  let now = 1000
  const reg = new AgentRegistry([cand('a', { priority: 10, cooldownMs: 100 }), cand('b', { priority: 50 })], { now: () => now })
  reg.reportFailure('a')
  reg.reportFailure('a')
  check('cooling before expiry', reg.select('mcp-security')?.id === 'b')
  now += 101
  check('recovers after cooldown', reg.select('mcp-security')?.id === 'a')
}

// ── 4. buildArgv：数组拼接，不拼字符串
{
  const c = cand('c')
  const arg = buildArgv(c, 'http://x/; rm -rf /', 0, { evidenceRoot: tmpRoot })
  check('argv is pure array append', JSON.stringify(arg.argv) === JSON.stringify(['true', 'scan', 'http://x/; rm -rf /']), arg.argv)
  check('single shell metachar arg stays one element', arg.argv.length === 3)
  check('attempt dir is created name', arg.evidenceDir.startsWith(tmpRoot))

  const noInvocation = buildArgv({ ...c, invocation: undefined }, 'x', 0, { evidenceRoot: tmpRoot })
  check('missing invocation is unsupported', noInvocation.supported === false)

  const a1 = buildArgv(c, 'x', 0, { evidenceRoot: tmpRoot })
  const a2 = buildArgv(c, 'x', 1, { evidenceRoot: tmpRoot })
  check('attempts never share a directory', a1.evidenceDir !== a2.evidenceDir)
}

// ── 5. classifyProcess
{
  check('ENOENT is agent-failure',
    classifyProcess({ exitCode: null, timedOut: false, stderr: '', spawnError: Object.assign(new Error('x'), { code: 'ENOENT' }) }).kind === 'agent-failure')
  check('EACCES is agent-failure',
    classifyProcess({ exitCode: null, timedOut: false, stderr: '', spawnError: Object.assign(new Error('x'), { code: 'EACCES' }) }).kind === 'agent-failure')
  check('timeout is agent-failure',
    classifyProcess({ exitCode: null, timedOut: true, stderr: '' }).kind === 'agent-failure')
  check('signal death is agent-failure',
    classifyProcess({ exitCode: null, timedOut: false, stderr: '' }).kind === 'agent-failure')

  // 核心：structured 必须压过退出码
  const withVerdict = classifyProcess({ exitCode: 100, timedOut: false, stderr: '', structured: { found: true } })
  check('structured verdict beats non-zero exit', withVerdict.kind === 'completed' && withVerdict.found === true, withVerdict)

  const cleanExit = classifyProcess({ exitCode: 0, timedOut: false, stderr: '' })
  check('exit 0 without verdict is inconclusive, not clean', cleanExit.kind === 'inconclusive', cleanExit)

  const usage = classifyProcess({ exitCode: 2, timedOut: false, stderr: 'Usage: foo --bar' })
  check('usage error is refused', usage.kind === 'refused', usage)

  const crash = classifyProcess({ exitCode: 1, timedOut: false, stderr: 'Traceback: boom' })
  check('exit 1 is agent-failure', crash.kind === 'agent-failure' && crash.reason.includes('Traceback'), crash)
}

// ── 6. verdict 解析器
{
  check('sarif empty is clean', sarifVerdict({ runs: [{ results: [] }] })?.found === false)
  check('sarif with results is found', sarifVerdict({ runs: [{ results: [{ level: 'error' }] }] })?.found === true)
  check('sarif garbage is unknown', sarifVerdict({}) === undefined)

  check('promptfoo all-error is unknown, not clean',
    promptfooVerdict({ results: { stats: { successes: 0, failures: 0, errors: 2 } } }) === undefined)
  check('promptfoo failures is found',
    promptfooVerdict({ results: { stats: { successes: 1, failures: 1, errors: 0 } } })?.found === true)
  check('promptfoo all-pass is clean',
    promptfooVerdict({ results: { stats: { successes: 3, failures: 0, errors: 0 } } })?.found === false)

  const dir = fs.mkdtempSync(path.join(tmpRoot, 'corvus-'))
  check('corvus without report is unknown', corvusVerdict({ stdout: '', stderr: '', exitCode: 0, evidenceDir: dir }) === undefined)

  fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify({
    findings: [
      { id: 'A', exploitation_confirmed: true },
      { id: 'B', exploitation_confirmed: false },
    ],
  }))
  const v = corvusVerdict({ stdout: '', stderr: '', exitCode: 0, evidenceDir: dir })
  check('corvus counts findings', v?.found === true)
  check('corvus reports confirmed subset', v?.detail.includes('1 exploitation-confirmed') === true, v)
}

// ── 7. dispatcher：失败降级
{
  const reg = new AgentRegistry([cand('first', { priority: 10 }), cand('second', { priority: 20 })])
  const calls = []
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async (c) => {
      calls.push(c.id)
      if (c.id === 'first') return { kind: 'agent-failure', reason: 'crash' }
      return { kind: 'completed', found: true, detail: '2 findings' }
    },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('failover reaches second agent', out.by === 'second' && out.settled === true && out.found === true)
  check('attempt chain records both', out.attempts.map((a) => a.result).join(',') === 'agent-failure,completed')
  check('failure counted against first', reg.list('mcp-security').find((a) => a.id === 'first')?.failures === 1)
  check('second is healthy', reg.list('mcp-security').find((a) => a.id === 'second')?.failures === 0)
  check('attempt records carry evidence dirs', out.attempts.every((a) => typeof a.evidenceDir === 'string' && a.evidenceDir.length > 0))
  check('each attempt has its own dir', out.attempts[0].evidenceDir !== out.attempts[1].evidenceDir)
}

// ── 8. dispatcher：completed 立即停
{
  const reg = new AgentRegistry([cand('only', { priority: 10 }), cand('backup', { priority: 20 })])
  let backupCalled = false
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async (c) => {
      if (c.id === 'backup') backupCalled = true
      return { kind: 'completed', found: false }
    },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('clean verdict settles on first agent', out.by === 'only' && out.found === false)
  check('backup never called', backupCalled === false)
  check('clean verdict does not failover', out.attempts.length === 1)
}

// ── 9. dispatcher：inconclusive 不计失败
{
  const reg = new AgentRegistry([cand('a', { priority: 10 }), cand('b', { priority: 20 })])
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async (c) => {
      if (c.id === 'a') return { kind: 'inconclusive', reason: 'no verdict' }
      return { kind: 'completed', found: false }
    },
  })
  const out = await dispatcher.dispatch(
    { direction: 'mcp-security', target: 't', secondOpinion: true },
    new AbortController().signal,
  )
  check('inconclusive fails over only when a second opinion is asked for', out.by === 'b')
  check('inconclusive does not count as failure',
    reg.list('mcp-security').find((x) => x.id === 'a')?.failures === 0)
  check('inconclusive agent stays selectable', reg.select('mcp-security')?.id === 'a')
}

// ── 10. dispatcher：refused 同 inconclusive
{
  const reg = new AgentRegistry([cand('r', { priority: 10 }), cand('ok', { priority: 20 })])
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async (c) =>
      c.id === 'r' ? { kind: 'refused', reason: 'unsupported' } : { kind: 'completed', found: true },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('refused fails over', out.by === 'ok')
  check('refused does not count as failure', reg.list('mcp-security').find((x) => x.id === 'r')?.failures === 0)
}

// ── 11. dispatcher：全部失败
{
  const reg = new AgentRegistry([cand('x', { priority: 10 }), cand('y', { priority: 20 })])
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async () => ({ kind: 'agent-failure', reason: 'boom' }),
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('all failing agents leave task unsettled', out.settled === false)
  check('unsettled reports last failure', out.failureReason === 'boom')
  check('both attempts recorded', out.attempts.length === 2)
}

// ── 12. dispatcher：unsupported kind 不计失败
{
  const reg = new AgentRegistry([
    { id: 'sub', direction: 'mcp-security', kind: 'subagent', capability: 's', priority: 10 },
    cand('cli-ok', { priority: 20 }),
  ])
  let cliCalls = 0
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async () => {
      cliCalls += 1
      return { kind: 'completed', found: false }
    },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('subagent kind is refused without calling attempt', out.attempts[0].result === 'refused' && cliCalls === 1)
  check('unsupported kind does not fail the agent', reg.list('mcp-security').find((x) => x.id === 'sub')?.failures === 0)
  check('falls through to cli', out.by === 'cli-ok')
}

// ── 13. dispatcher：attempt 抛错不炸整个派活
{
  const reg = new AgentRegistry([cand('throws', { priority: 10 }), cand('fine', { priority: 20 })])
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async (c) => {
      if (c.id === 'throws') throw new Error('exec layer exploded')
      return { kind: 'completed', found: true }
    },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('throwing attempt is a failure, not a crash', out.attempts[0].result === 'agent-failure')
  check('throwing attempt still fails over', out.by === 'fine')
}

// ── 14. dispatcher：abort
{
  const reg = new AgentRegistry([cand('a'), cand('b', { priority: 20 })])
  const controller = new AbortController()
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async () => {
      controller.abort()
      return { kind: 'agent-failure', reason: 'stopped' }
    },
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't' }, controller.signal)
  check('abort stops further attempts', out.attempts.length === 1)
  check('abort leaves task unsettled', out.settled === false)
}

// ── 15. maxAttempts 上限
{
  const reg = new AgentRegistry([cand('a', { priority: 1 }), cand('b', { priority: 2 }), cand('c', { priority: 3 })])
  const dispatcher = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async () => ({ kind: 'agent-failure', reason: 'x' }),
  })
  const out = await dispatcher.dispatch({ direction: 'mcp-security', target: 't', maxAttempts: 2 }, new AbortController().signal)
  check('maxAttempts caps the chain', out.attempts.length === 2)
}

// ── 15b. rabin2 verdict：保护缺失才算发现
{
  const mk = (info) => rabinVerdict({ stdout: JSON.stringify({ info }), stderr: '', exitCode: 0, evidenceDir: '/' })
  check('rabin2 hardened is clean', mk({ bintype: 'elf', arch: 'x86', canary: true, nx: true, pic: true, relro: 'full' })?.found === false)
  check('rabin2 no canary is found', mk({ bintype: 'elf', arch: 'x86', canary: false, nx: true, pic: true, relro: 'full' })?.found === true)
  check('rabin2 relro none is found', mk({ bintype: 'elf', arch: 'x86', canary: true, nx: true, pic: true, relro: 'none' })?.found === true)
  check('rabin2 garbage is unknown', mk({ arch: 'x86' }) === undefined)
}

// ── 15c. claim 关联必须是显式字段，不能静默失效
{
  const reg = new AgentRegistry([cand('a')])
  const noClaim = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    attempt: async () => ({ kind: 'completed', found: true }),
  })
  const r1 = await noClaim.dispatch({ direction: 'mcp-security', target: 't', claimId: 'claim-1' }, new AbortController().signal)
  check('claim without executor support reports claimLinked=false', r1.claimLinked === false, r1.claimLinked)

  const reg2 = new AgentRegistry([cand('a')])
  const withClaim = new DirectionalDispatcher({
    registry: reg2,
    evidenceRoot: tmpRoot,
    supportsClaim: true,
    attempt: async () => ({ kind: 'completed', found: true }),
  })
  const r2 = await withClaim.dispatch({ direction: 'mcp-security', target: 't', claimId: 'claim-1' }, new AbortController().signal)
  check('declared support reports claimLinked=true', r2.claimLinked === true)

  const reg3 = new AgentRegistry([cand('a')])
  const noClaimId = new DirectionalDispatcher({
    registry: reg3,
    evidenceRoot: tmpRoot,
    supportsClaim: true,
    attempt: async () => ({ kind: 'completed', found: true }),
  })
  const r3 = await noClaimId.dispatch({ direction: 'mcp-security', target: 't' }, new AbortController().signal)
  check('no claim id means nothing to link', r3.claimLinked === false)
}

// ── 15d. 渲染文本必须带全关键字段
// 上一轮踩过：schema 加了字段但 render 没加，模型看不到，只能回一句 NOT_RETURNED。
{
  const text = renderDispatch({
    settled: true,
    found: false,
    by: 'rabin2',
    detail: 'elf/x86',
    claim_linked: true,
    attempts: [{ agent: 'rabin2', result: 'completed', evidence_dir: '/tmp/x' }],
  })
  for (const key of ['settled=true', 'found=false', 'by=rabin2', 'claim_linked=true', 'detail=elf/x86']) {
    check(`render carries ${key}`, text.includes(key), text)
  }
  check('render lists attempts', text.includes('rabin2 result=completed'), text)
  check('render points at the evidence dir', text.includes('evidence=/tmp/x'), text)

  const settledByString = renderDispatch({ settled: true, found: true, by: 'x' })
  check('render never emits natural-language settled', !settledByString.includes('settled by'), settledByString)
}

// ── 15e. 目标形态识别
{
  const dir = fs.mkdtempSync(path.join(tmpRoot, 'shape-'))
  const txt = path.join(dir, 'a.txt')
  fs.writeFileSync(txt, 'hello')
  const bin = path.join(dir, 'a.bin')
  // 最小 ELF 头：\x7fELF
  fs.writeFileSync(bin, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]))

  check('shape url', detectTargetShape('https://example.test/a') === 'url')
  check('shape directory', detectTargetShape(dir) === 'directory')
  check('shape file', detectTargetShape(txt) === 'file')
  check('shape binary', detectTargetShape(bin) === 'binary')
  check('shape command', detectTargetShape('python3 /tmp/x.py') === 'command')
  check('shape host', detectTargetShape('example.test') === 'host')
  check('shape ip', detectTargetShape('10.0.0.5') === 'host')
  check('shape host with port', detectTargetShape('example.test:8443') === 'host')
  check('shape unknown', detectTargetShape('@@@ nonsense @@@') === 'unknown')
  // 路径存在性优先于命令判定：带空格的路径不能被当成命令
  const spaced = path.join(dir, 'with space.txt')
  fs.writeFileSync(spaced, 'x')
  check('spaced path is file not command', detectTargetShape(spaced) === 'file')
}

// ── 15f. 适配度决定派谁
{
  check('declared match is 1', fitness({ id: 'a', direction: 'mcp-security', kind: 'cli', capability: 'x', accepts: ['file'] }, 'file') === 1)
  check('declared mismatch is 0', fitness({ id: 'a', direction: 'mcp-security', kind: 'cli', capability: 'x', accepts: ['file'] }, 'url') === 0)
  check('undeclared is neutral', fitness({ id: 'a', direction: 'mcp-security', kind: 'cli', capability: 'x' }, 'url') === 0.5)

  const reg = new AgentRegistry([
    { id: 'cmd-first', direction: 'mcp-security', kind: 'cli', capability: 'eats commands', priority: 1, accepts: ['command'] },
    { id: 'file-second', direction: 'mcp-security', kind: 'cli', capability: 'eats config files', priority: 50, accepts: ['file'] },
  ])
  check('file target ranks the file agent first', reg.available('mcp-security', 'file')[0].id === 'file-second')
  check('command target ranks the command agent first', reg.available('mcp-security', 'command')[0].id === 'cmd-first')
  check('without shape it stays priority order', reg.available('mcp-security')[0].id === 'cmd-first')
}

// ── 15g. 停手：形态不匹配就不跑
{
  const reg = new AgentRegistry([
    { id: 'bin-only', direction: 'mcp-security', kind: 'cli', capability: 'x', accepts: ['binary'], invocation: () => ['y'] },
  ])
  let called = 0
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'url',
    attempt: async () => {
      called += 1
      return { kind: 'completed', found: true }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'https://x' }, new AbortController().signal)
  check('no-fit stops before running anything', called === 0 && out.stopReason === 'no-fit', out)
  check('no-fit is not settled', out.settled === false)
}

// ── 15h. 停手：代价预算
{
  const reg = new AgentRegistry([
    { id: 'e1', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'expensive', priority: 1, invocation: () => ['y'] },
    { id: 'e2', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'expensive', priority: 2, invocation: () => ['y'] },
  ])
  const seen = []
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    policy: { costBudget: 10, faultCircuit: 9, maxAttempts: 5 },
    attempt: async (c) => {
      seen.push(c.id)
      return { kind: 'agent-failure', reason: 'exit 1: boom' }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'x' }, new AbortController().signal)
  check('expensive agent consumes the whole budget in one run', seen.length === 1 && seen[0] === 'e1', seen)
  check('cost-budget is the stop reason', out.stopReason === 'cost-budget', out.stopReason)
  check('cost spent is reported', out.costSpent === 10, out.costSpent)
}

// ── 15i. 停手：同类故障熔断
{
  const reg = new AgentRegistry([
    { id: 't1', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 1, invocation: () => ['y'] },
    { id: 't2', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 2, invocation: () => ['y'] },
    { id: 't3', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 3, invocation: () => ['y'] },
  ])
  const seen = []
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    policy: { costBudget: 99, maxAttempts: 5, faultCircuit: 2 },
    attempt: async (c) => {
      seen.push(c.id)
      return { kind: 'agent-failure', reason: 'timed out' }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'x' }, new AbortController().signal)
  check('two identical faults open the circuit', seen.length === 2, seen)
  check('fault-circuit is the stop reason', out.stopReason === 'fault-circuit', out.stopReason)
}

// ── 15j. 不同类故障不熔断，继续换
{
  const reg = new AgentRegistry([
    { id: 'f1', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 1, invocation: () => ['y'] },
    { id: 'f2', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 2, invocation: () => ['y'] },
    { id: 'f3', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 3, invocation: () => ['y'] },
  ])
  const seen = []
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    policy: { costBudget: 99, maxAttempts: 3, faultCircuit: 2 },
    attempt: async (c) => {
      seen.push(c.id)
      if (c.id === 'f1') return { kind: 'agent-failure', reason: 'timed out' }
      if (c.id === 'f2') return { kind: 'agent-failure', reason: 'executable not found (ENOENT)' }
      return { kind: 'completed', found: true }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'x' }, new AbortController().signal)
  check('distinct faults do not trip the circuit', seen.length === 3, seen)
  check('third agent still settles', out.by === 'f3' && out.stopReason === 'settled')
}

// ── 15k. 跑通没定论：默认停手，交回主控
{
  const reg = new AgentRegistry([
    { id: 'i1', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 1, invocation: () => ['y'] },
    { id: 'i2', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 2, invocation: () => ['y'] },
  ])
  const seen = []
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    attempt: async (c) => {
      seen.push(c.id)
      return { kind: 'inconclusive', reason: 'exit 0 without structured verdict' }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'x' }, new AbortController().signal)
  check('default policy stops after one inconclusive', seen.length === 1, seen)
  check('inconclusive is the stop reason', out.stopReason === 'inconclusive', out.stopReason)
  check('untried candidates are reported back', out.untried?.some((u) => u.agent === 'i2') === true, out.untried)

  const seen2 = []
  const d2 = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    attempt: async (c) => {
      seen2.push(c.id)
      return { kind: 'inconclusive', reason: 'no verdict' }
    },
  })
  const out2 = await d2.dispatch({ direction: 'mcp-security', target: 'x', secondOpinion: true }, new AbortController().signal)
  check('second opinion doubles the allowance and keeps going', seen2.length === 2, seen2)
  check('second opinion raises the cost budget', out2.stopReason !== 'cost-budget', out2.stopReason)
}

// ── 15l. 尝试次数上限
{
  const reg = new AgentRegistry([
    { id: 'm1', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 1, invocation: () => ['y'] },
    { id: 'm2', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 2, invocation: () => ['y'] },
    { id: 'm3', direction: 'mcp-security', kind: 'cli', capability: 'x', cost: 'cheap', priority: 3, invocation: () => ['y'] },
  ])
  const seen = []
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot: tmpRoot,
    detectShape: () => 'file',
    policy: { costBudget: 99, maxAttempts: 2, faultCircuit: 9 },
    attempt: async (c) => {
      seen.push(c.id)
      return c.id === 'm1'
        ? { kind: 'agent-failure', reason: 'timed out' }
        : { kind: 'agent-failure', reason: 'executable not found (ENOENT)' }
    },
  })
  const out = await d.dispatch({ direction: 'mcp-security', target: 'x' }, new AbortController().signal)
  check('maxAttempts caps the chain', seen.length === 2, seen)
  check('max-attempts is the stop reason', out.stopReason === 'max-attempts', out.stopReason)
}

// ── 16. 默认清单的自洽性
{
  const reg = new AgentRegistry(DEFAULT_AGENTS)
  const dirs = reg.summary()
  check('default registry builds', dirs.length > 0)
  check('every default candidate has a capability', DEFAULT_AGENTS.every((a) => typeof a.capability === 'string' && a.capability.length > 10))
  check('cli candidates declare command', DEFAULT_AGENTS.filter((a) => a.kind === 'cli').every((a) => Array.isArray(a.command) && a.command.length > 0))
  check('cli candidates without invocation declare requires',
    DEFAULT_AGENTS.filter((a) => a.kind === 'cli' && a.invocation === undefined).every((a) => typeof a.requires === 'string'))
  const aiDirs = dirs.filter((d) => d.direction === 'ai-security')
  check('ai-security has multiple candidates', aiDirs.length === 1 && aiDirs[0].total >= 2)
  check('every runnable cli agent declares a cost tier',
    DEFAULT_AGENTS.filter((a) => a.kind === 'cli' && a.invocation !== undefined).every((a) => a.cost !== undefined))
  check('every runnable cli agent declares accepted shapes',
    DEFAULT_AGENTS.filter((a) => a.kind === 'cli' && a.invocation !== undefined).every((a) => Array.isArray(a.accepts) && a.accepts.length > 0))
  check('every runnable cli agent declares its own patience',
    DEFAULT_AGENTS.filter((a) => a.kind === 'cli' && a.invocation !== undefined).every((a) => typeof a.defaultTimeoutMs === 'number' && a.defaultTimeoutMs > 0))
  check('the slowest tools get the longest timeouts',
    (DEFAULT_AGENTS.find((a) => a.id === 'nuclei')?.defaultTimeoutMs ?? 0) > (DEFAULT_AGENTS.find((a) => a.id === 'rabin2')?.defaultTimeoutMs ?? 0))
  check('expensive agents are not default picks',
    DEFAULT_AGENTS.filter((a) => a.cost === 'expensive').every((a) => (a.priority ?? 100) >= 20))
}

fs.rmSync(tmpRoot, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
