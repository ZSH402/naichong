/**
 * 数据画像 + 范式停滞验收。
 *
 * 两件事：量形状要准（判错格式 = 后面全错），
 * 判「在搜而不是在推」要能穿透「每次写的脚本都不一样」。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { profileData } from '../dist/data-profile.js'
import { detectSearchApproach, approachReminder, StallDetector } from '../dist/stall-guard.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-profile-'))
const write = (name, content) => { const p = path.join(dir, name); fs.writeFileSync(p, content); return p }

// ── 1. 格式判定
{
  const j = write('a.json', JSON.stringify({ a: 1, b: [1,2] }))
  check('json detected', profileData(j)?.kind === 'json', profileData(j)?.kind)

  const jsonl = write('a.jsonl', '{"x":1}\n{"x":2}\n{"x":3}\n')
  check('jsonl detected as json', profileData(jsonl)?.kind === 'json')

  const csv = write('a.csv', 'host,port,status\na,80,open\nb,443,closed\nc,22,open\n')
  const pc = profileData(csv)
  check('csv detected', pc?.kind === 'csv', pc?.kind)
  check('csv delimiter found', pc?.delimiter === ',', pc?.delimiter)

  const kv = write('a.conf', 'user=admin\npass=secret\nhost=1.2.3.4\nport=22\n')
  check('key-value detected', profileData(kv)?.kind === 'key-value', profileData(kv)?.kind)

  const rule = write('a.rules', 'a -> b\na, c -> d\n-b -> e\nc -> -a, f\n')
  const pr = profileData(rule)
  check('rule graph detected', pr?.kind === 'rule-graph', pr?.kind)
  check('rule graph verdict points at structure', /关系|规则图/.test(pr?.verdict ?? ''), pr?.verdict)

  const log = write('a.log', '[2026-01-01 10:00:00] GET /a\n[2026-01-01 10:00:01] GET /b\n')
  check('logs detected', profileData(log)?.kind === 'log-lines', profileData(log)?.kind)

  const bin = path.join(dir, 'a.bin')
  fs.writeFileSync(bin, Buffer.from([0,1,2,3,0,1,2,3,0,1,2,3]))
  check('binary detected', profileData(bin)?.kind === 'binary', profileData(bin)?.kind)

  const txt = write('a.txt', 'hello world\nfoo bar baz\nqux quux\n')
  check('plain text detected', profileData(txt)?.kind === 'text', profileData(txt)?.kind)

  check('missing file returns undefined', profileData(path.join(dir, 'nope')) === undefined)
}

// ── 2. 重复度：模板生成的数据要先归类
{
  const p = write('dup.log', Array.from({length: 100}, (_, i) => `line template A ${i}`).join('\n'))
  const prof = profileData(p)
  check('repeated templates raise the duplicate ratio', prof.duplicateRatio > 0.9, prof.duplicateRatio)
  check('verdict mentions the template pattern', /模板|归类/.test(prof.verdict), prof.verdict)
}

// ── 3. 搜索类工作的识别
{
  for (const s of ['python3 sim.py', 'cat > brute.py <<EOF', 'for i in itertools.permutations(x)', 'while True: enumerate(all)', 'for a in range(100): for b in range(100):']) {
    check(`detects search: ${s.slice(0,32)}`, detectSearchApproach(s) !== undefined, s)
  }
  for (const s of ['curl https://x/api', 'nmap -sV 10.0.0.1', 'grep -n user app.log', 'cat config.yaml']) {
    check(`not search: ${s.slice(0,32)}`, detectSearchApproach(s) === undefined)
  }
}

// ── 4. 范式停滞需要连续才会触发
{
  const d = new StallDetector({ window: 12, threshold: 5 })
  d.noteApproach('python3 sim.py')
  check('one attempt is not a streak', d.searchStalled() === undefined)
  d.noteApproach('cat > brute.py')
  check('two attempts still not', d.searchStalled() === undefined)
  d.noteApproach('python3 enum.py')
  const s = d.searchStalled()
  check('three attempts escalate', s !== undefined && s.streak === 3, s)
}

// ── 5. 提醒说方法而不是骂人
{
  const t = approachReminder('brute-force', 3)
  check('reminder names the streak', t.includes('3'))
  check('reminder asks about search space size', /空间|2\^256|量级/.test(t))
  check('reminder says solve not search', /解/.test(t))
  check('reminder warns about self-written parsers', /解析器|验证/.test(t))
  check('reminder does not scold', !/不许|严禁|违规/.test(t))
}

fs.rmSync(dir, { recursive: true, force: true })
const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
