/**
 * 逐个副 agent 验收：每一个都真派一次活，看它是否被选中、是否拿回结果。
 *
 * 方向级验证会掩盖问题——一个方向只要有一个能用的 agent 就算过，
 * 剩下的坏掉完全看不出来。这个文件一个一个点名测。
 *
 * 判定口径：
 *   settled / inconclusive —— 通路成立（后者是「跑通了但没有结构化判据」，合法）
 *   agent-failure          —— 坏了，必须修
 *   refused                —— 本层不支持，说明接线缺一块
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { execFileSync } from 'node:child_process'
import { AgentRegistry, DEFAULT_AGENTS, probeAgents } from '../dist/agent-registry.js'
import { defaultMcpBindings } from '../dist/mcp-bindings.js'
import { DirectionalDispatcher } from '../dist/agent-dispatch.js'
import { createQueueAttempt } from '../dist/agent-tools.js'
import { QueueRunner } from '../dist/queue-runner.js'
import { CoverageLedger } from '../dist/coverage.js'
import { ClaimStore } from '../dist/provenance-tools.js'
import { AdapterRegistry } from '../dist/council/contract.js'
import { createCliToolAdapter } from '../dist/council/adapters.js'
import { createMcpAdapter, closeAllMcpClients } from '../dist/council/mcp-adapter.js'
import { ArtexClient, createArtexAdapter } from '../dist/council/artex-adapter.js'
import { Marshal } from '../dist/council/marshal.js'
import { Censor } from '../dist/council/censor.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail).slice(0, 260)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-each-'))
const work = path.join(root, 'work')
fs.mkdirSync(work, { recursive: true })
process.env.LLM_API_KEY = process.env.LLM_API_KEY ?? process.env.OPENAI_API_KEY ?? ''
process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? process.env.LLM_API_KEY ?? ''

const registry = new AgentRegistry(DEFAULT_AGENTS)
probeAgents(registry)

const runner = new QueueRunner({
  queueFile: path.join(root, 'q.jsonl'),
  evidenceRoot: path.join(root, 'ev'),
  concurrency: 2,
  // 上界要盖住最慢那张牌（strix 的 defaultTimeoutMs 是 30 分钟）。
  // 派活自己的 timeoutMs 仍按候选取值，这里只是队列的兜底。
  defaultTimeoutMs: 1_900_000,
})
runner.start()
const dispatcher = new DirectionalDispatcher({
  registry,
  evidenceRoot: path.join(root, 'ev'),
  maxAttempts: 1,
  attempt: createQueueAttempt(runner, { cwd: work }),
})

// ── 靶子 ──
const www = path.join(root, 'www')
fs.mkdirSync(www, { recursive: true })
fs.writeFileSync(path.join(www, 'index.html'), 'fixture')
const httpSrv = spawn('python3', ['-m', 'http.server', '18083', '--bind', '127.0.0.1'], { cwd: www, stdio: 'ignore' })

const tlsDir = path.join(root, 'tls')
fs.mkdirSync(tlsDir, { recursive: true })
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(tlsDir, 'k.pem'),
  '-out', path.join(tlsDir, 'c.pem'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
const tlsSrv = spawn('openssl', ['s_server', '-accept', '18445', '-cert', path.join(tlsDir, 'c.pem'),
  '-key', path.join(tlsDir, 'k.pem'), '-www'], { stdio: 'ignore' })

// promptfoo 需要一份 config
const pfCfg = path.join(work, 'promptfooconfig.yaml')
fs.writeFileSync(pfCfg, 'prompts:\n  - "refuse: {{x}}"\nproviders:\n  - echo\ntests:\n  - vars: {x: a}\n    assert:\n      - type: contains\n        value: "refuse"\n')

// corvus 需要 MCP server 作目标
process.env.PATH = `${process.env.PATH}:/root/proj/agents/venvs/semgrep/bin`

await new Promise((r) => setTimeout(r, 2500))

/** 点名派给某个候选。 */
const hit = async (agentId, direction, target, budgetMs = 300_000) => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), budgetMs)
  const startedAt = Date.now()
  try {
    const out = await dispatcher.dispatch({ direction, target, preferAgentId: agentId, maxAttempts: 1, timeoutMs: budgetMs }, controller.signal)
    return { out, elapsed: Date.now() - startedAt }
  } finally {
    clearTimeout(timer)
  }
}

const judge = (agentId, r, opts = {}) => {
  if (r.out === undefined) {
    check(`${agentId}: 派活`, false, { error: 'no outcome' })
    return
  }
  const t = r.out.attempts[0]
  const got = t?.agentId === agentId
  check(`${agentId}: 被点名选中`, got, { picked: t?.agentId })
  const outcome = t?.result
  const ok = outcome === 'completed' || outcome === 'inconclusive'
  const detail = t?.detail ?? t?.reason ?? ''
  if (ok) {
    check(`${agentId}: 拿回结果 (${r.elapsed}ms)`, true)
    console.log(`      → ${outcome} / found=${String(r.out.found)} / ${String(detail).slice(0, 90)}`)
  } else if (opts.tolerate !== undefined && String(detail).includes(opts.tolerate)) {
    check(`${agentId}: 按预期不可用（${opts.tolerate}）`, true)
    console.log(`      → ${outcome} / ${String(detail).slice(0, 110)}`)
  } else {
    check(`${agentId}: 拿回结果`, false, { outcome, detail: String(detail).slice(0, 200) })
  }
}

console.log('# 逐个派活\n')

// ── 本地 CLI ──
judge('rabin2', await hit('rabin2', 'binary-reverse', '/usr/bin/ls'))
judge('checksec', await hit('checksec', 'binary-reverse', '/usr/bin/ls'))
judge('sslyze', await hit('sslyze', 'crypto', 'localhost:18445'))
judge('nuclei', await hit('nuclei', 'web-pentest', 'http://127.0.0.1:18083', 600_000))
judge('enum4linux-ng', await hit('enum4linux-ng', 'internal-ad', '127.0.0.1', 300_000))
judge('promptfoo', await hit('promptfoo', 'ai-security', pfCfg, 240_000))
judge('rea', await hit('rea', 'binary-reverse', '/usr/bin/ls', 240_000), { tolerate: 'provider_unavailable' })
// radare2 与 rea 同方向但不依赖公开引擎：它是 binary 方向的兜底牌。
judge('radare2', await hit('radare2', 'binary-reverse', '/usr/bin/ls', 240_000))
// corvus：mcp-security 方向唯一的可用牌。target 是 MCP server 的**启动命令**
// （corvus 会自己拉起来再测），不是 URL。全量 34 模块约 5.5 分钟。
judge('corvus', await hit('corvus', 'mcp-security', `${CS}/cyberstrike-mcp -config ${CS}/config.example.yaml`, 600_000))

// ── MCP（CyberStrikeAI）──
const CS = '/root/proj/agents/cyberstrike/CyberStrikeAI-main'
const csBin = path.join(CS, 'cyberstrike-mcp')
if (fs.existsSync(csBin)) {
  const mcp = createMcpAdapter({
    spec: { command: [csBin, '-config', path.join(CS, 'config.example.yaml')], cwd: CS, timeoutMs: 120_000 },
    bindings: defaultMcpBindings(),
    logger: { info: () => {}, warn: () => {} },
  })
  const contract = (id, direction, target) => ({
    id: `each-${id}`, kind: 'mcp', direction, target, agentId: id,
    estimatedCost: 1, requestedBy: 'marshal', rationale: 'each-agent check',
  })
  for (const [id, direction, target, budget] of [
    ['cyberstrike-nmap', 'internal-ad', '127.0.0.1', 180_000],
    ['cyberstrike-dirsearch', 'web-pentest', 'http://127.0.0.1:18083', 300_000],
    ['cyberstrike-sqlmap', 'web-pentest', 'http://127.0.0.1:18083', 300_000],
    ['cyberstrike-ghidra', 'binary-reverse', '/usr/bin/ls', 300_000],
  ]) {
    const c = new AbortController()
    const timer = setTimeout(() => c.abort(), budget)
    const startedAt = Date.now()
    try {
      const r = await mcp.execute(contract(id, direction, target), { signal: c.signal })
      const ok = r.outcome === 'settled' || r.outcome === 'inconclusive'
      check(`${id}: 拿回结果 (${Date.now() - startedAt}ms)`, ok, { outcome: r.outcome, reason: r.reason, detail: r.detail })
      if (ok) console.log(`      → ${r.outcome} / found=${String(r.found)} / ${String(r.detail ?? r.reason ?? '').slice(0, 90)}`)
    } catch (error) {
      check(`${id}: 拿回结果`, false, { error: String(error) })
    } finally {
      clearTimeout(timer)
    }
  }
  closeAllMcpClients()
} else {
  console.log('SKIP  MCP：找不到 cyberstrike-mcp')
}

// ── 外部执行体：ARTEX ──
{
  const client = new ArtexClient({ baseUrl: 'http://127.0.0.1:8787', password: process.env.ARTEX_PASSWORD ?? 'artex-local-dev-2026' })
  if (await client.health()) {
    const a = createArtexAdapter(client, { logger: { info: () => {}, warn: () => {} } })
    const c = new AbortController()
    const timer = setTimeout(() => c.abort(), 240_000)
    try {
      const r = await a.execute(
        { id: 'each-artex', kind: 'agent', direction: 'web-pentest', target: 'http://127.0.0.1:18083',
          estimatedCost: 3, requestedBy: 'marshal', rationale: 'each-agent check', timeoutMs: 180_000 },
        { signal: c.signal },
      )
      const ok = r.outcome === 'settled' || r.outcome === 'inconclusive'
      check(`artex: 拿回结果`, ok, { outcome: r.outcome, reason: r.reason, detail: r.detail })
      if (ok) console.log(`      → ${r.outcome} / found=${String(r.found)} / ${String(r.detail ?? r.reason ?? '').slice(0, 100)}`)
    } catch (error) {
      check('artex: 拿回结果', false, { error: String(error) })
    } finally {
      clearTimeout(timer)
    }
  } else {
    console.log('SKIP  ARTEX：服务未运行')
  }
}

// ── strix（最慢，放最后）──
// strix 的 requiresEnv 是 LLM_API_KEY / OPENAI_API_KEY。没有 key 时它会被判
// 不可用，派活静默回退到 nuclei——那样「拿回结果」会 PASS，但测的根本不是 strix。
// 所以没 key 就 SKIP 并说清，而不是让 PASS 冒充覆盖。
if ((process.env.LLM_API_KEY ?? process.env.OPENAI_API_KEY ?? '') === '') {
  console.log('SKIP  strix：未设置 LLM_API_KEY/OPENAI_API_KEY，派活会回退到 nuclei，测不出 strix')
} else {
  // strix 默认最多 80 轮 LLM 循环，15 分钟只是「跑到一半」。
  // 实测小预算短跑（8 轮 / $1）能在几分钟内 exit 0 并写出 findings.sarif；
  // 完整扫描要给到它自己声明的 30 分钟，否则测的是超时而不是 agent。
  judge('strix', await hit('strix', 'web-pentest', 'http://127.0.0.1:18083', 1_800_000))
}

httpSrv.kill()
tlsSrv.kill()
runner.close()
await runner.drain()
fs.rmSync(root, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
