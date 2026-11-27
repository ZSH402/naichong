/**
 * 黑盒语料层验收：RFC 微灵感、跨目标共振、参数进化。
 *
 * 这三块的共同点：**都不靠模型生成内容**。
 *   intel      —— 从 RFC 原文提取规范性断言，原语全部指向真实段落
 *   resonance   —— MinHash 聚类，跨目标同簇才抬优先级
 *   evolve      —— nevergrad 搜参数，评分来自靶场真实检出
 *
 * 验收重点在"依据可核查"：每条原语能不能点开本地 RFC 核对，
 * 每个簇的判定是不是基于目标数而不是观察数。
 */
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + String(JSON.stringify(d) ?? d).slice(0, 300)}`)
}

const ENGINE = '/root/异构agent/engine'
const cli = async (args, timeout = 600_000) => {
  try {
    const { stdout } = await execFileAsync('python3', ['-m', 'blackbox.cli', ...args], {
      maxBuffer: 32 * 1024 * 1024, timeout, cwd: ENGINE,
    })
    return JSON.parse(stdout.trim().split('\n').pop() ?? '{}')
  } catch (err) {
    const e = err
    if (typeof e.stdout === 'string' && e.stdout.trim() !== '') {
      try { return JSON.parse(e.stdout.trim().split('\n').pop() ?? '{}') } catch { /* fallthrough */ }
    }
    return { error: String(e.message ?? 'failed').slice(0, 300) }
  }
}

// ── 1. RFC 微灵感
{
  const r = await cli(['intel', '--base', 'x'], 180_000)
  check('载入了本地 RFC 语料', Array.isArray(r.sources?.rfcs_available) && r.sources.rfcs_available.length >= 5,
    r.sources?.rfcs_available)
  check('RFC 原文有实际字节数', (r.sources?.rfc_downloaded_bytes ?? 0) > 500_000, r.sources?.rfc_downloaded_bytes)
  check('提取出规范性断言', (r.normative_claims ?? 0) > 50, r.normative_claims)
  check('生成了探针原语', (r.primitives ?? 0) >= 10, r.primitives)
  check('生成缓存层探针', (r.cache_probes ?? 0) >= 3, r.cache_probes)
  check('接入了 SecLists 语料', (r.edge_strings ?? 0) > 0, r.edge_strings)

  // 每条原语都必须能在本地 RFC 里找到依据
  const backed = r.sources?.primitives_with_local_rfc ?? []
  const unbacked = r.sources?.primitives_without_local_rfc ?? []
  check('所有原语都有本地 RFC 依据', unbacked.length === 0, { backed: backed.length, unbacked })

  // 定义段落（"MUST", "MUST NOT"…）不应被当成断言
  const sample = r.sample_claims ?? []
  check('没有把关键词定义段当成断言',
    sample.every((c) => (c.text.match(/"/g) ?? []).length <= 4), sample.slice(0, 2))
  check('断言带 RFC 号与节号', sample.every((c) => c.rfc && typeof c.section === 'string'),
    sample.slice(0, 2))
}

// ── 2. 跨目标共振
{
  const obs = JSON.stringify([
    { target: 'a', kind: 'stack-trace', endpoint: '/api/debug', detail: 'stack frame leaked: Traceback File /root/app/main.py' },
    { target: 'b', kind: 'stack-trace', endpoint: '/debug', detail: 'stack frame leaked: File /home/app/server.py' },
    { target: 'a', kind: 'length-blowup', endpoint: '/list', detail: 'body 90000 bytes baseline max 2000' },
  ])
  const r = await cli(['resonance', '--base', 'x', '--observations', obs], 120_000)
  check('聚类跑通', (r.clusters ?? 0) >= 1, r.clusters)
  check('识别出跨目标共振簇', (r.resonant_clusters ?? 0) === 1, r.resonant_clusters)
  const res = (r.detail ?? []).find((c) => c.resonant === true)
  check('共振簇包含两个不同目标', res?.target_count === 2, res?.targets)
  check('单目标簇不判为共振', (r.detail ?? []).some((c) => c.resonant === false), r.detail?.map((c) => c.resonant))

  // 同一个目标上的两条相似观察不应构成共振
  const same = JSON.stringify([
    { target: 'a', kind: 'stack-trace', endpoint: '/x', detail: 'stack frame leaked: Traceback File /root/a.py' },
    { target: 'a', kind: 'stack-trace', endpoint: '/y', detail: 'stack frame leaked: Traceback File /root/b.py' },
  ])
  const r2 = await cli(['resonance', '--base', 'x', '--observations', same], 120_000)
  check('同一目标的重复观察不算共振', (r2.resonant_clusters ?? 0) === 0, r2)
}

// ── 3. 参数进化（评分来自靶场真实检出）
{
  const r = await cli(['evolve', '--base', 'x', '--port', '8127', '--budget', '4', '--seed', '2'], 700_000)
  check('进化跑通', typeof r.engine === 'string' && r.engine !== '', r.engine)
  check('产出最优参数', r.best !== undefined && typeof r.best.concurrency === 'number', r.best)
  check('参数落在搜索空间内',
    r.best.concurrency >= 4 && r.best.concurrency <= 32 && r.best.rounds >= 1 && r.best.rounds <= 6, r.best)
  check('评分来自真实检出而非自评',
    Array.isArray(r.best_detail?.detected) && r.best_detail.detected.length > 0, r.best_detail)
  check('记录了每代历史', Array.isArray(r.history) && r.history.length === 4, r.history?.length)
  check('明确说明只进化参数不改逻辑', /parameter evolution only/.test(r.note ?? ''), r.note?.slice(0, 80))
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
