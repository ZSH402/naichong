/**
 * 全链路验收：一个目标进去，三公走出来，副 agent 干活，报告出来。
 *
 * 之前所有的测试都在验证零件——每个 agent 单独能跑、council 每个类单独对。
 * 但没人验证过**零件接起来还能不能转**。这个文件只做一件事：
 * 对每个方向真跑一次 Council.run，看它有没有把活派给对的执行者、有没有拿回结论。
 *
 * 不通过 LLM 调工具，直接构造 Council——这样测的是编排链路本身，
 * 不受模型随机性的影响。模型能不能正确调用是另一回事（wiring.mjs 管那个）。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { AgentRegistry, DEFAULT_AGENTS, probeAgents } from '../dist/agent-registry.js'
import { DirectionalDispatcher } from '../dist/agent-dispatch.js'
import { createQueueAttempt } from '../dist/agent-tools.js'
import { QueueRunner } from '../dist/queue-runner.js'
import { ClaimStore } from '../dist/provenance-tools.js'
import { CoverageLedger } from '../dist/coverage.js'
import { Council } from '../dist/council/index.js'
import { createMcpAdapter, closeAllMcpClients } from '../dist/council/mcp-adapter.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail).slice(0, 300)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-fullchain-'))
const work = path.join(root, 'work')
fs.mkdirSync(work, { recursive: true })

// LLM 凭据：strix 需要
process.env.LLM_API_KEY = process.env.LLM_API_KEY ?? process.env.OPENAI_API_KEY ?? ''
process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? process.env.LLM_API_KEY ?? ''

const registry = new AgentRegistry(DEFAULT_AGENTS)
const probe = probeAgents(registry)
console.log(`# 可用 ${String(probe.available.length - probe.missing.length)} 个，缺 ${String(probe.missing.length)} 个\n`)

const store = new ClaimStore()
const runner = new QueueRunner({
  queueFile: path.join(root, 'q.jsonl'),
  evidenceRoot: path.join(root, 'ev'),
  concurrency: 2,
  defaultTimeoutMs: 300_000,
})
runner.start()
const coverage = new CoverageLedger()
const dispatcher = new DirectionalDispatcher({
  registry,
  evidenceRoot: path.join(root, 'ev'),
  maxAttempts: 1,
  attempt: createQueueAttempt(runner, { cwd: work }),
})

// CyberStrikeAI 的 MCP（如果二进制在）
const CS = '/root/proj/agents/cyberstrike/CyberStrikeAI-main'
const csBin = path.join(CS, 'cyberstrike-mcp')
const csCfg = path.join(CS, 'config.example.yaml')
const mcpAdapter = fs.existsSync(csBin)
  ? createMcpAdapter({
      spec: { command: [csBin, '-config', csCfg], cwd: CS, timeoutMs: 60_000 },
      bindings: new Map([
        [
          'cyberstrike-nmap',
          {
            tool: 'nmap',
            args: (c) => ({ target: c.target.split(':')[0], timing: '4' }),
            verdict: (r) => {
              const open = [...r.text.matchAll(/^(\d+\/tcp)\s+open\s+(\S+)/gm)]
              return open.length === 0 ? undefined : { found: true, detail: open.slice(0, 4).map((m) => `${m[1]} ${m[2]}`).join(', ') }
            },
          },
        ],
      ]),
      logger: { info: () => {}, warn: () => {} },
    })
  : undefined

const council = new Council({
  registry,
  dispatcher,
  claims: store,
  coverage,
  paths: { roster: path.join(root, 'roster.jsonl'), board: path.join(root, 'board.jsonl') },
  ...(mcpAdapter === undefined ? {} : { mcpAdapter }),
  logger: { info: () => {}, warn: () => {} },
})

// ── 靶子 ──
const httpSrv = spawn('python3', ['-m', 'http.server', '18082'], { cwd: fs.mkdirSync(path.join(root, 'www'), { recursive: true }) ?? root, stdio: 'ignore' })
fs.writeFileSync(path.join(root, 'www', 'index.html'), 'fixture')
const tlsDir = path.join(root, 'tls')
fs.mkdirSync(tlsDir, { recursive: true })
const { execFileSync } = await import('node:child_process')
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(tlsDir, 'k.pem'),
  '-out', path.join(tlsDir, 'c.pem'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
const tlsSrv = spawn('openssl', ['s_server', '-accept', '18444', '-cert', path.join(tlsDir, 'c.pem'),
  '-key', path.join(tlsDir, 'k.pem'), '-www'], { stdio: 'ignore' })
const auditDir = path.join(root, 'audit')
fs.mkdirSync(auditDir, { recursive: true })
fs.writeFileSync(path.join(auditDir, 'v.py'), 'import subprocess\ndef h(r):\n    return subprocess.check_output(r, shell=True)\n')
fs.writeFileSync(path.join(tlsDir, 'empty.txt'), '')
await new Promise((r) => setTimeout(r, 2500))

const runDirection = async (direction, target, budgetMs = 180_000) => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), budgetMs)
  const startedAt = Date.now()
  try {
    const { summary, plan } = await council.run({
      target,
      directions: [direction],
      maxTasks: 1,
      signal: controller.signal,
    })
    return { summary, plan, elapsed: Date.now() - startedAt }
  } catch (error) {
    return { error: String(error), elapsed: Date.now() - startedAt }
  } finally {
    clearTimeout(timer)
  }
}

const report = (label, r) => {
  if (r.error !== undefined) {
    check(`${label}: council.run 未抛错`, false, { error: r.error, elapsed: r.elapsed })
    return
  }
  const t = r.summary.results[0]
  // 判据：真的派了活、真的拿回了非失败非拦截的终态。
  const ok = r.summary.results.length > 0 && t !== undefined && (t.outcome === 'settled' || t.outcome === 'inconclusive')
  check(
    `${label}: 派活并拿回结果`,
    ok,
    {
      results: r.summary.results.length,
      outcome: t?.outcome,
      agent: t?.agentId,
      reason: t?.reason,
      skipped: r.plan.skipped,
      elapsed: r.elapsed,
    },
  )
  if (t !== undefined) {
    console.log(`      → ${t.contract.direction} / ${t.agentId ?? '?'} / ${t.outcome} / found=${String(t.found ?? 'n/a')} / ${(t.detail ?? t.reason ?? '').slice(0, 90)}`)
  }
}

// ── 逐方向 ──
report('binary-reverse', await runDirection('binary-reverse', '/usr/bin/ls'))
report('code-audit', await runDirection('code-audit', auditDir))
report('crypto', await runDirection('crypto', 'localhost:18444'))
report('web-pentest', await runDirection('web-pentest', 'http://127.0.0.1:18082'))
report('internal-ad', await runDirection('internal-ad', '127.0.0.1'))

httpSrv.kill()
tlsSrv.kill()
closeAllMcpClients()
runner.close()
await runner.drain()
fs.rmSync(root, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
