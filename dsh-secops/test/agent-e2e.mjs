/**
 * 方向级调度端到端验收：真跑已装好的 agent，看结论是否落在证据上。
 *
 * 这个测试刻意不 mock 执行层——只有真跑才能证明「vocation 契约 + verdict 解析 +
 * 进程判定」这三段是接上的。任何一段错位，结论就会退化成 inconclusive 或假阳性。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { AgentRegistry, DEFAULT_AGENTS, nucleiVerdict, semgrepVerdict } from '../dist/agent-registry.js'
import { DirectionalDispatcher } from '../dist/agent-dispatch.js'
import { createQueueAttempt } from '../dist/agent-tools.js'
import { QueueRunner } from '../dist/queue-runner.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-e2e-'))
const evidenceRoot = path.join(root, 'evidence')
const workdir = path.join(root, 'work')
fs.mkdirSync(evidenceRoot, { recursive: true })
fs.mkdirSync(workdir, { recursive: true })

const runner = new QueueRunner({
  queueFile: path.join(root, 'queue.jsonl'),
  evidenceRoot,
  concurrency: 2,
  defaultTimeoutMs: 180_000,
})
runner.start()

const registry = new AgentRegistry(DEFAULT_AGENTS)
const dispatcher = new DirectionalDispatcher({
  registry,
  evidenceRoot,
  attempt: createQueueAttempt(runner, { cwd: workdir }),
})

const signal = new AbortController().signal

// ── 1. MCP 安全：corvus 扫 fixture MCP server
{
  const fixture = '/root/异构agent/dsh-secops/fixtures/fixture-mcp-server.py'
  if (!fs.existsSync(fixture)) {
    check('corvus: fixture exists', false)
  } else {
    const out = await dispatcher.dispatch(
      { direction: 'mcp-security', target: `python3 ${fixture}`, timeoutMs: 120_000 },
      signal,
    )
    check('corvus reaches a verdict', out.settled === true, out)
    check('corvus reports findings on a deliberately sloppy server', out.found === true, out)
    check('corvus is the settling agent', out.by === 'corvus', out.by)
    check('corvus detail counts findings', typeof out.detail === 'string' && /\d+ (result|finding)/.test(out.detail), out.detail)
    const dir = out.attempts[0]?.evidenceDir
    check('corvus wrote a SARIF report', dir !== undefined && fs.existsSync(path.join(dir, 'report.sarif')))
    check('corvus stdout archived', dir !== undefined && fs.existsSync(path.join(dir, 'stdout.log')))
  }
}

// ── 2. AI 安全：promptfoo 跑一个必失败的断言
{
  const cfg = path.join(workdir, 'promptfooconfig.yaml')
  fs.writeFileSync(
    cfg,
    [
      'prompts:',
      '  - "refuse this: {{x}}"',
      'providers:',
      '  - echo',
      'tests:',
      '  - vars: { x: alpha }',
      '    assert:',
      '      - type: contains',
      '        value: "refuse"',
      '  - vars: { x: beta }',
      '    assert:',
      '      - type: contains',
      '        value: "MUST_BE_ABSENT"',
      '',
    ].join('\n'),
  )
  const out = await dispatcher.dispatch({ direction: 'ai-security', target: cfg, timeoutMs: 120_000 }, signal)
  check('promptfoo reaches a verdict', out.settled === true, out)
  check('promptfoo is the settling agent', out.by === 'promptfoo', out.by)
  check('promptfoo failing assertion counts as found', out.found === true, out)
  check('promptfoo detail has the pass/fail split', typeof out.detail === 'string' && /1 pass \/ 1 fail/.test(out.detail), out.detail)
}

// ── 3. 二进制逆向：rabin2 读加固状态
{
  const out = await dispatcher.dispatch({ direction: 'binary-reverse', target: '/usr/bin/ls', timeoutMs: 30_000 }, signal)
  check('rabin2 reaches a verdict', out.settled === true, out)
  check('rabin2 is the settling agent', out.by === 'rabin2', out.by)
  check('rabin2 detail names the binary type', typeof out.detail === 'string' && out.detail.includes('elf'), out.detail)
  // 不断言 found 的具体值：发行版的 /usr/bin/ls 加固程度随打包策略变化，
  // 断言它就变成在测发行版而不是测我们的代码。
}

// ── 3b. 代码审计：semgrep 扫一段必命中注入规则的源码
{
  const src = path.join(workdir, 'audit')
  fs.mkdirSync(src, { recursive: true })
  fs.writeFileSync(
    path.join(src, 'v.py'),
    'import subprocess\ndef handler(request):\n    return subprocess.check_output(request.args.get("cmd"), shell=True)\n',
  )
  // 用本地规则而不是 --config auto：后者要去 registry 拉规则，
  // 网络一慢就表现为超时，测出来的就不是我们的代码而是网速。
  const rules = path.join(workdir, 'rules.yaml')
  fs.writeFileSync(
    rules,
    [
      'rules:',
      '  - id: py-subprocess-injection',
      '    languages: [python]',
      '    severity: ERROR',
      '    message: user input reaches subprocess with shell=True',
      '    patterns:',
      '      - pattern: subprocess.check_output(...)',
      '      - pattern-inside: |',
      '          def $F(...):',
      '            ...',
      '',
    ].join('\n'),
  )
  const semgrepReg = new AgentRegistry([
    {
      id: 'semgrep',
      direction: 'code-audit',
      kind: 'cli',
      command: ['/root/proj/agents/venvs/semgrep/bin/semgrep'],
      capability: 'local-rule semgrep for the test',
      priority: 10,
      accepts: ['directory', 'file'],
      cost: 'cheap',
      invocation: (target) => ['--config', rules, '--json', '--quiet', target],
      verdict: semgrepVerdict,
    },
  ])
  const semgrepOnly = new DirectionalDispatcher({
    registry: semgrepReg,
    evidenceRoot,
    attempt: createQueueAttempt(runner, { cwd: workdir }),
  })
  const out = await semgrepOnly.dispatch({ direction: 'code-audit', target: src, timeoutMs: 180_000 }, signal)
  check('semgrep reaches a verdict', out.settled === true, out)
  check('semgrep is the settling agent', out.by === 'semgrep', out.by)
  check('semgrep finds the subprocess injection', out.found === true, out)
  check('semgrep detail counts matches', typeof out.detail === 'string' && /\d+ match/.test(out.detail), out.detail)
}

// ── 3c. Web 渗透：nuclei 扫本地靶子
// 生产 invocation 跑全模板集（几分钟）；这里收窄到 exposure 标签，
// 测的是「契约 → 进程判定 → JSONL 解析」这条链，不是 nuclei 自己快不快。
{
  const http = await import('node:http')
  const srv = http.createServer((req, res) => {
    if (req.url === '/.env') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('DB_PASSWORD=hunter2\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n')
      return
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><body>fixture</body></html>')
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  const port = srv.address().port

  const fastReg = new AgentRegistry([
    {
      id: 'nuclei',
      direction: 'web-pentest',
      kind: 'cli',
      command: ['nuclei'],
      capability: 'narrowed to exposure templates for the test',
      priority: 10,
      invocation: (target) => ['-u', target, '-jsonl', '-silent', '-nc', '-duc', '-tags', 'exposure'],
      verdict: nucleiVerdict,
    },
  ])
  const fast = new DirectionalDispatcher({
    registry: fastReg,
    evidenceRoot,
    attempt: createQueueAttempt(runner, { cwd: workdir }),
  })

  const out = await fast.dispatch({ direction: 'web-pentest', target: `http://127.0.0.1:${port}`, timeoutMs: 240_000 }, signal)
  check('nuclei reaches a verdict', out.settled === true, out)
  check('nuclei is the settling agent', out.by === 'nuclei', out.by)
  check('nuclei finds the exposed .env', out.found === true, out)
  check('nuclei detail counts matches', typeof out.detail === 'string' && /\d+ match/.test(out.detail), out.detail)
  srv.close()
}

// ── 3d. 二进制：checksec 对未加固样本报缺失
{
  const src = path.join(workdir, 'u.c')
  const bin = path.join(workdir, 'unhardened')
  fs.writeFileSync(src, 'int main(){char b[8];return b[0];}\n')
  const built = await new Promise((resolve) => {
    import('node:child_process').then(({ execFile }) => {
      execFile('gcc', ['-fno-stack-protector', '-no-pie', '-z', 'execstack', '-o', bin, src], (err) =>
        resolve(err === null),
      )
    })
  })
  if (!built) {
    check('checksec: gcc available for fixture build', false)
  } else {
    const out = await dispatcher.dispatch({ direction: 'binary-reverse', target: bin, timeoutMs: 60_000 }, signal)
    check('checksec reaches a verdict', out.settled === true, out)
    check('checksec finds the missing mitigations', out.found === true, out)
    check('checksec names what is missing', typeof out.detail === 'string' && /canary/.test(out.detail), out.detail)
  }
}

// ── 3e. 内网：enum4linux-ng 对本地 SMB 靶子报空会话
// 需要一个在 445 上监听的本机 SMB 服务；没有就跳过，不假装测过。
{
  const listening = await new Promise((resolve) => {
    import('node:net').then(({ createConnection }) => {
      const sock = createConnection({ host: '127.0.0.1', port: 445 })
      sock.on('connect', () => { sock.destroy(); resolve(true) })
      sock.on('error', () => resolve(false))
      sock.setTimeout(2000, () => { sock.destroy(); resolve(false) })
    })
  })
  if (!listening) {
    console.log('SKIP  enum4linux-ng: no SMB service on 127.0.0.1:445')
  } else {
    const out = await dispatcher.dispatch({ direction: 'internal-ad', target: '127.0.0.1', timeoutMs: 180_000 }, signal)
    check('enum4linux-ng reaches a verdict', out.settled === true, out)
    check('enum4linux-ng is the settling agent', out.by === 'enum4linux-ng', out.by)
    check('enum4linux-ng flags the null session', out.found === true, out)
    check('enum4linux-ng detail mentions the session', typeof out.detail === 'string' && /session|guest/i.test(out.detail), out.detail)
  }
}

// ── 3f. 密码学：sslyze 对本地 TLS 靶子报废弃协议
{
  const { execFileSync } = await import('node:child_process')
  const tlsDir = path.join(workdir, 'tls')
  fs.mkdirSync(tlsDir, { recursive: true })
  const key = path.join(tlsDir, 'k.pem')
  const cert = path.join(tlsDir, 'c.pem')
  const listening = await new Promise((resolve) => {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert, '-days', '1',
      '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
    resolve(fs.existsSync(key))
  })
  if (!listening) {
    console.log('SKIP  sslyze: could not build a TLS fixture')
  } else {
    const { spawn } = await import('node:child_process')
    const srv = spawn('openssl', ['s_server', '-accept', '18443', '-cert', cert, '-key', key, '-www'], { stdio: 'ignore' })
    await new Promise((r) => setTimeout(r, 1500))
    try {
      const out = await dispatcher.dispatch({ direction: 'crypto', target: 'localhost:18443', timeoutMs: 180_000 }, signal)
      check('sslyze reaches a verdict', out.settled === true, out)
      check('sslyze is the settling agent', out.by === 'sslyze', out.by)
      check('sslyze flags the deprecated protocols', out.found === true, out)
      check('sslyze names TLS 1.0/1.1', /TLS 1\.[01]/.test(out.detail ?? ''), out.detail)
    } finally {
      srv.kill()
    }
  }
}

// ── 4. 缺依赖的 agent 被跳过而不是反复重试
{
  const reg = new AgentRegistry([
    {
      id: 'ghost',
      direction: 'mcp-security',
      kind: 'cli',
      command: ['definitely-not-a-real-binary-xyz'],
      capability: 'missing on purpose',
      priority: 1,
      // 与 corvus 声明同样的形态，才能让优先级决定顺序——
      // 否则适配度高的 corvus 会先跑，这条测试就测不到降级而是测到"选得对"。
      accepts: ['command'],
      invocation: () => ['x'],
    },
    ...DEFAULT_AGENTS.filter((a) => a.direction === 'mcp-security'),
  ])
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot,
    attempt: createQueueAttempt(runner, { cwd: workdir }),
  })
  const fixture = '/root/异构agent/dsh-secops/fixtures/fixture-mcp-server.py'
  const out = await d.dispatch({ direction: 'mcp-security', target: `python3 ${fixture}`, timeoutMs: 120_000 }, signal)
  check('missing binary is classified as agent-failure', out.attempts[0]?.result === 'agent-failure', out.attempts[0])
  check('missing binary falls over to a real agent', out.settled === true && out.by === 'corvus', out)
  check('missing binary got failures counted', reg.list('mcp-security').find((a) => a.id === 'ghost')?.failures === 1)
}

// ── 4b. 适配度高的候选先跑，哪怕它的优先级更低
{
  const reg = new AgentRegistry([
    {
      id: 'ghost-open',
      direction: 'mcp-security',
      kind: 'cli',
      command: ['definitely-not-a-real-binary-xyz'],
      capability: 'no shape declaration, priority 1',
      priority: 1,
      invocation: () => ['x'],
    },
    ...DEFAULT_AGENTS.filter((a) => a.direction === 'mcp-security'),
  ])
  const d = new DirectionalDispatcher({
    registry: reg,
    evidenceRoot,
    attempt: createQueueAttempt(runner, { cwd: workdir }),
  })
  const fixture = '/root/异构agent/dsh-secops/fixtures/fixture-mcp-server.py'
  const out = await d.dispatch({ direction: 'mcp-security', target: `python3 ${fixture}`, timeoutMs: 120_000 }, signal)
  check('exact shape match outranks a lower-priority wildcard',
    out.attempts[0]?.agentId === 'corvus' && out.attempts[0]?.fitness === 1, out.attempts[0])
  check('shape was detected as an mcp launch command', out.shape === 'command', out.shape)
  check('wildcard agent left untried and reported', out.untried?.some((u) => u.agent === 'ghost-open') === true, out.untried)
}

// ── 5. 不存在的方向
{
  const out = await dispatcher.dispatch({ direction: 'crypto', target: 'x' }, signal)
  check('empty direction leaves task unsettled', out.settled === false)
  check('empty direction records no attempts', out.attempts.length === 0)
}

runner.close()
await runner.drain()
fs.rmSync(root, { recursive: true, force: true })

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
