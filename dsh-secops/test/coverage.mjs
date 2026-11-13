/**
 * 覆盖账本验收。
 *
 * 核心是那条三态区分：**「没测过」和「测了没发现」必须分得开**，
 * 把前者当后者，就是漏报最隐蔽的来源。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { CoverageLedger } from '../dist/coverage.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-cov-'))

// ── 1. 空账本：只能说「未记录」
{
  const l = new CoverageLedger()
  const c = l.of('host-a', ['web', 'code'])
  check('empty ledger is not-recorded', c.state === 'not-recorded', c.state)
  check('verdict refuses to say "not scanned"', /未记录/.test(c.verdict) && !/^未扫描/.test(c.verdict), c.verdict)
}

// ── 2. 别处有记录，这里没有 → 未扫描
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'host-a', check: 'web', status: 'complete', outputs: 0 })
  const other = l.of('host-b', ['web'])
  check('untouched asset is not-scanned', other.state === 'not-scanned', other.state)
  check('gap names the missing check', other.gaps.includes('web'), other.gaps)
}

// ── 3. 全部完成且无缺口 → covered
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'a', check: 'web', status: 'complete', outputs: 2 })
  l.stamp({ asset: 'a', check: 'code', status: 'complete', outputs: 0 })
  const c = l.of('a', ['web', 'code'])
  check('all checks complete means covered', c.state === 'covered', c.state)
  check('no gaps when covered', c.gaps.length === 0, c.gaps)
  check('outputs are preserved', c.stamps.find((s) => s.check === 'web')?.outputs === 2)
}

// ── 4. 有缺口 → partial
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'a', check: 'web', status: 'complete' })
  const c = l.of('a', ['web', 'code'])
  check('missing a check means partial', c.state === 'partial', c.state)
  check('gap lists code', c.gaps.includes('code'), c.gaps)
}

// ── 5. 失败和部分都算 partial，不算覆盖
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'a', check: 'web', status: 'failed', reason: 'timeout' })
  const c = l.of('a', ['web'])
  check('failed check is not coverage', c.state === 'partial', c.state)
  check('reason survives', c.stamps[0]?.reason === 'timeout', c.stamps[0])
}

// ── 6. no-input 等于没测
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'a', check: 'web', status: 'no-input', reason: 'no urls' })
  const c = l.of('a', ['web'])
  check('no-input is treated as not scanned', c.state === 'not-scanned', c.state)
  check('verdict explains it', /no-input/.test(c.verdict) || /等于没测/.test(c.verdict), c.verdict)
}

// ── 7. last-wins 与持久化
{
  const p = path.join(dir, 'cov.jsonl')
  const l = new CoverageLedger(p)
  l.stamp({ asset: 'a', check: 'web', status: 'failed' })
  l.stamp({ asset: 'a', check: 'web', status: 'complete', outputs: 1 })
  check('later stamp overwrites earlier', l.of('a').stamps.length === 1)
  check('overwritten status is complete', l.of('a').stamps[0]?.status === 'complete')

  const l2 = new CoverageLedger(p)
  check('ledger survives reload', l2.size === 2, l2.size)
  check('reloaded state matches', l2.of('a').state === 'covered', l2.of('a').state)
}

// ── 8. 摘要只报有缺口的
{
  const l = new CoverageLedger()
  l.stamp({ asset: 'done', check: 'web', status: 'complete' })
  l.stamp({ asset: 'half', check: 'web', status: 'complete' })
  const s = l.summary(['web', 'code'])
  const names = s.gaps.map((g) => g.asset)
  check('summary lists the incomplete asset', names.includes('half'), names)
  check('summary omits the fully covered one for missing checks', s.gaps.find((g) => g.asset === 'done')?.missing.length === 1, s.gaps)
  check('summary reports recorded=true', s.recorded === true)
}

fs.rmSync(dir, { recursive: true, force: true })
const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
