/**
 * 奖惩信誉验收。
 *
 * 要防的三种失败：
 *   一、小样本虚假高分（1 次成功 = 100%，排在 100 次成功 90 次的老牌前面）
 *   二、一次失手永久弃用（信誉系统最常见的过度反应）
 *   三、奖惩把「能不能用」和「准不准」混成一个数（适配度是硬条件，信誉是软偏好）
 */
import { AgentRegistry, DEFAULT_AGENTS } from '../dist/agent-registry.js'
import {
  DEFAULT_HALF_LIFE_MS,
  MIN_SHAPE_SAMPLE,
  recencyWeight,
  tallyByShape,
  tallyRelevance,
  CREDIT_CEIL,
  CREDIT_FLOOR,
  CREDIT_NEUTRAL,
  CreditBoard,
  betaPosterior,
  creditScore,
  exploreBonus,
  tallyVerdicts,
} from '../dist/council/credit.js'
import { Roster } from '../dist/council/roster.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}
const near = (a, b, eps = 0.005) => Math.abs(a - b) <= eps

// ── 1. Beta 后验：先验就是惩罚地板
{
  check('no history is neutral', near(betaPosterior(0, 0), 0.5), betaPosterior(0, 0))
  check('one success lifts', near(betaPosterior(1, 0), 2 / 3), betaPosterior(1, 0))
  check('one failure lowers but does not destroy', near(betaPosterior(0, 1), 1 / 3), betaPosterior(0, 1))
  check('five successes', near(betaPosterior(5, 0), 6 / 7), betaPosterior(5, 0))
  check('five failures', near(betaPosterior(0, 5), 1 / 7), betaPosterior(0, 5))
  // 关键性质：一次失败后仍严格大于 0。Wilson 在这里给的是 0，等于永久否决。
  check('one failure never reaches zero', betaPosterior(0, 1) > 0, betaPosterior(0, 1))
  check('symmetry: one win == one loss complement', near(betaPosterior(1, 0) + betaPosterior(0, 1), 1))
  // 一对成功+失败回到中性 —— 这就是「可恢复」的数学形式
  check('win+loss returns to neutral', near(betaPosterior(1, 1), CREDIT_NEUTRAL), betaPosterior(1, 1))
  check('monotone in successes', betaPosterior(3, 1) > betaPosterior(2, 1))
  check('monotone in failures', betaPosterior(1, 3) < betaPosterior(1, 2))
}

// ── 2. 探索项：跑得少加分多，且没跑过时有确定有限值
{
  const w = 0.15
  const total = 100
  check('unrun agents get a finite bonus', Number.isFinite(exploreBonus(0, total, w)) && exploreBonus(0, total, w) > 0, exploreBonus(0, total, w))
  check('bonus shrinks with runs', exploreBonus(0, total, w) > exploreBonus(5, total, w), [exploreBonus(0, total, w), exploreBonus(5, total, w)])
  check('bonus grows with global volume', exploreBonus(3, 1000, w) > exploreBonus(3, 10, w))
  check('weight 0 disables exploration', exploreBonus(0, total, 0) === 0)
}

// ── 3. 总分：赢过的在前，没试过的还有机会，失过手的往后但不除名
{
  const total = 100
  const s = (c, r, runs) => creditScore({ agent: 'x', confirmed: c, refuted: r, runs }, total, {})
  const win5 = s(5, 0, 5)
  const win1 = s(1, 0, 1)
  const fresh = s(0, 0, 0)
  const lose1 = s(0, 1, 1)
  const lose5 = s(0, 5, 5)

  check('proven winners rank first', win5.value > win1.value && win1.value > fresh.value, [win5.value, win1.value, fresh.value])
  check('fresh sits above a single miss', fresh.value > lose1.value, [fresh.value, lose1.value])
  check('repeat offender sinks', lose1.value > lose5.value, [lose1.value, lose5.value])
  check('ceiling is respected', win5.value <= CREDIT_CEIL, win5.value)
  check('floor is respected', lose5.value >= CREDIT_FLOOR, lose5.value)
  check('a single miss keeps most of its standing', lose1.value / fresh.value > 0.6, lose1.value / fresh.value)
  check('basis is human readable', /confirmed/.test(win5.basis) && /posterior/.test(win5.basis), win5.basis)
  check('no-history basis says so', /no evidence yet/.test(fresh.basis), fresh.basis)
}

// ── 4. 统计口径：按 claim 计数、只算归因、只算已定论
{
  const ev = (tool) => ({
    ref: `r-${tool}`,
    pathKey: `tool:${tool}`,
    source: { kind: 'worker', taskId: 't', argv: [`/usr/bin/${tool}`, '-x'], cwd: '/tmp' },
    addedAt: 1,
  })
  const claim = (o) => ({ id: o.id, claim: o.id, status: o.status, evidence: o.evidence, independentPaths: 1, createdAt: 1, updatedAt: 1, blame: o.blame })
  const claims = [
    claim({ id: 'c1', status: 'confirmed', evidence: [ev('nmap')] }),
    claim({ id: 'c2', status: 'confirmed', evidence: [ev('nmap'), ev('nuclei')] }),
    claim({ id: 'c3', status: 'refuted', evidence: [ev('nuclei')], blame: ['nuclei'] }),
    // 被推翻但归因到另一个工具：nuclei 在这条里的证据仍然成立，不该记它一笔
    claim({ id: 'c4', status: 'refuted', evidence: [ev('nuclei'), ev('dirsearch')], blame: ['dirsearch'] }),
    // 没有定论：不进分母
    claim({ id: 'c5', status: 'hypothesis', evidence: [ev('nmap')] }),
  ]
  const t = tallyVerdicts(claims)
  check('nmap: two confirmed, one open ignored', t.get('nmap')?.confirmed === 2 && t.get('nmap')?.refuted === 0, t.get('nmap'))
  check('nuclei: one confirmed, one blamed refutation', t.get('nuclei')?.confirmed === 1 && t.get('nuclei')?.refuted === 1, t.get('nuclei'))
  check('dirsearch: blamed even though another tool shares the claim', t.get('dirsearch')?.refuted === 1, t.get('dirsearch'))
  check('open claims do not enter the tally', t.get('nmap')?.confirmed === 2, t.get('nmap'))
}

// ── 5. 面板与有效优先级
{
  const board = new CreditBoard({ exploreWeight: 0.15 })
  board.refresh([])
  check('unknown agent scores neutral', near(board.scoreOf('nobody').value, CREDIT_NEUTRAL), board.scoreOf('nobody').value)
  check('unknown agent keeps its priority', near(board.effectivePriority('nobody', 10), 10), board.effectivePriority('nobody', 10))
  check('neutral keeps priority unchanged', near(board.effectivePriority('nobody', 40), 40), board.effectivePriority('nobody', 40))

  const ev = (tool) => ({
    ref: `r-${tool}`,
    pathKey: `tool:${tool}`,
    source: { kind: 'worker', taskId: 't', argv: [tool], cwd: '/tmp' },
    addedAt: 1,
  })
  const mk = (id, status, tool, blame) => ({
    id,
    claim: id,
    status,
    evidence: [ev(tool)],
    independentPaths: 1,
    createdAt: 1,
    updatedAt: 1,
    ...(blame === undefined ? {} : { blame }),
  })
  const claims = [
    mk('a', 'confirmed', 'good'),
    mk('b', 'confirmed', 'good'),
    mk('c', 'confirmed', 'good'),
    mk('d', 'refuted', 'bad', ['bad']),
    mk('e', 'refuted', 'bad', ['bad']),
    mk('f', 'refuted', 'bad', ['bad']),
  ]
  board.refresh(claims)
  const good = board.scoreOf('good')
  const bad = board.scoreOf('bad')
  check('good agent scores above neutral', good.value > CREDIT_NEUTRAL, good.value)
  check('bad agent scores below neutral', bad.value < CREDIT_NEUTRAL, bad.value)
  check('good agent priority shrinks', board.effectivePriority('good', 20) < 20, board.effectivePriority('good', 20))
  check('bad agent priority grows', board.effectivePriority('bad', 20) > 20, board.effectivePriority('bad', 20))
  check('ordering is reported sorted', board.all()[0]?.agent === 'good', board.all().map((x) => x.agent))
}

// ── 6. roster 只喂探索项，不污染准确率
{
  const roster = new Roster()
  roster.record({ agentId: 'busy', outcome: 'failed' })
  roster.record({ agentId: 'busy', outcome: 'failed' })
  roster.record({ agentId: 'busy', outcome: 'failed' })
  const board = new CreditBoard({ exploreWeight: 0.15 })
  board.refresh([], roster)
  const busy = board.scoreOf('busy')
  check('execution failures do not touch accuracy', busy.posterior === CREDIT_NEUTRAL && busy.sample === 0, busy)
  check('but they do reduce the exploration bonus', busy.explore < board.scoreOf('idle').explore, [busy.explore, board.scoreOf('idle').explore])
}

// ── 7. 注册表排序：信誉只在适配度相同处生效
{
  const reg = new AgentRegistry(DEFAULT_AGENTS)
  const ids = (list) => list.map((c) => c.id)
  const base = ids(reg.available('web-pentest', 'url'))
  check('without credit the order is priority-based', base[0] === 'nuclei', base)

  const demolished = ids(reg.available('web-pentest', 'url', { creditOf: (id) => (id === 'nuclei' ? 0.1 : undefined) }))
  check('a discredited agent falls back', demolished.indexOf('nuclei') > demolished.indexOf('strix'), demolished)
  check('but it is never removed', demolished.includes('nuclei'), demolished)
  check('nothing else changes', demolished.filter((x) => x !== 'nuclei').join() === base.filter((x) => x !== 'nuclei').join(), demolished)

  // 适配度是硬条件：binary 方向里吃不下 binary 形态的牌，信誉再高也排不到能吃的牌前面
  const binary = reg.available('binary-reverse', 'binary', { creditOf: () => 0.98 })
  const fits = binary.filter((c) => c.accepts?.includes('binary') !== false)
  check('fitness still gates the order', fits.length > 0 && binary.length > 0, { fits: fits.length, all: binary.length })
}

// ── 8. 与 precision 口径一致（同一份数据不能算出两个答案）
{
  const ev = (tool) => ({
    ref: `r-${tool}`,
    pathKey: `tool:${tool}`,
    source: { kind: 'worker', taskId: 't', argv: [tool], cwd: '/tmp' },
    addedAt: 1,
  })
  const mk = (id, status, tool, blame) => ({
    id,
    claim: id,
    status,
    evidence: [ev(tool)],
    independentPaths: 1,
    createdAt: 1,
    updatedAt: 1,
    ...(blame === undefined ? {} : { blame }),
  })
  const claims = [mk('a', 'confirmed', 't1'), mk('b', 'refuted', 't1', ['t1']), mk('c', 'refuted', 't1', [])]
  const tally = tallyVerdicts(claims)
  const { analyzePrecision } = await import('../dist/council/precision.js')
  const p = analyzePrecision(claims).agents.find((a) => a.agent === 't1')
  check('confirmed counts agree with precision', tally.get('t1')?.confirmed === p?.confirmed, { tally: tally.get('t1'), precision: p })
  check('refuted counts agree with precision', tally.get('t1')?.refuted === p?.refuted, { tally: tally.get('t1'), precision: p })
}

// ── 9. 时间衰减：老战绩打折，但不会消失
{
  const now = Date.UTC(2026, 10, 12)
  const D = 86_400_000
  check('fresh evidence is full weight', near(recencyWeight(now, now, 90 * D), 1), recencyWeight(now, now, 90 * D))
  check('one half-life halves it', near(recencyWeight(now - 90 * D, now, 90 * D), 0.5), recencyWeight(now - 90 * D, now, 90 * D))
  check('two half-lives quarter it', near(recencyWeight(now - 180 * D, now, 90 * D), 0.25))
  check('old evidence never reaches exactly zero', recencyWeight(now - 3650 * D, now, 90 * D) > 0)
  check('halfLife 0 disables decay', recencyWeight(now - 3650 * D, now, 0) === 1)
  check('future timestamps do not amplify', recencyWeight(now + 90 * D, now, 90 * D) === 1)
  check('default half-life is 90 days', DEFAULT_HALF_LIFE_MS === 90 * D, DEFAULT_HALF_LIFE_MS)

  const ev = { ref: 'e', pathKey: 'p', addedAt: 1, source: { kind: 'worker', taskId: 't', argv: ['checksec'], cwd: '/' } }
  const mk = (id, status, at, blame) => ({
    id, claim: id, status, evidence: [ev], independentPaths: 1, createdAt: at, updatedAt: at,
    ...(blame === undefined ? {} : { blame }),
  })
  const claims = [
    mk('a', 'confirmed', now),
    mk('b', 'confirmed', now),
    mk('old', 'refuted', now - 400 * D, ['checksec']),
  ]
  const decayed = tallyVerdicts(claims, { now, halfLifeMs: 90 * D }).get('checksec')
  check('decay keeps the raw count for display', decayed.confirmed === 2 && decayed.refuted === 1, decayed)
  check('decay shrinks the weighted count', decayed.effectiveRefuted < 0.1, decayed)
  const flat = tallyVerdicts(claims, { now, halfLifeMs: 0 }).get('checksec')
  check('halfLife 0 keeps the full weight', flat.effectiveRefuted === 1, flat)

  const board = new CreditBoard({ halfLifeMs: 90 * D, now: () => now })
  board.refresh(claims)
  check('an ancient miss barely dents the score', board.scoreOf('checksec').value > 0.7, board.scoreOf('checksec').value)
  check('basis says the counts were aged', /aged to/.test(board.scoreOf('checksec').basis), board.scoreOf('checksec').basis)
}

// ── 10. 形态分层：同一张牌在不同形态上可以完全不同
{
  const now = Date.now()
  const ev = { ref: 'e', pathKey: 'p', addedAt: 1, source: { kind: 'worker', taskId: 't', argv: ['nuclei'], cwd: '/' } }
  const mk = (id, status, shape, blame) => ({
    id, claim: id, status, evidence: [ev], independentPaths: 1, createdAt: now, updatedAt: now,
    ...(shape === undefined ? {} : { shape }),
    ...(blame === undefined ? {} : { blame }),
  })
  const claims = [
    mk('a1', 'confirmed', 'url'), mk('a2', 'confirmed', 'url'), mk('a3', 'confirmed', 'url'),
    mk('b1', 'refuted', 'directory', ['nuclei']),
    mk('b2', 'refuted', 'directory', ['nuclei']),
    mk('b3', 'refuted', 'directory', ['nuclei']),
    // 没有形态的：只进全局，不进任何桶
    mk('c1', 'refuted', undefined, ['nuclei']),
  ]
  const byShape = tallyByShape(claims, { now, halfLifeMs: 0 })
  check('url bucket holds three wins', byShape.get('nuclei@url')?.confirmed === 3, byShape.get('nuclei@url'))
  check('directory bucket holds three losses', byShape.get('nuclei@directory')?.refuted === 3, byShape.get('nuclei@directory'))
  check('shapeless claims do not land in a bucket', byShape.get('nuclei') === undefined, [...byShape.keys()])

  const board = new CreditBoard({ halfLifeMs: 0, now: () => now })
  board.refresh(claims)
  const global = board.scoreOf('nuclei').value
  const onUrl = board.scoreOf('nuclei', 'url').value
  const onDir = board.scoreOf('nuclei', 'directory').value
  const untested = board.scoreOf('nuclei', 'binary').value
  // 全局 = 3 confirmed + 4 refuted（3 条 directory + 1 条 shapeless）→ Beta(4,5) = 4/9
  check('global folds shapes and shapeless alike', near(global, 4 / 9, 0.01), global)
  check('url shape ranks well above global', onUrl > global + 0.2, { onUrl, global })
  check('directory shape ranks well below global', onDir < global - 0.2, { onDir, global })
  check('untested shape falls back to global', near(untested, global), { untested, global })
  check('shapeView only lists well-sampled shapes', board.shapeView().every((s) => s.rawSample >= MIN_SHAPE_SAMPLE), board.shapeView())

  // 样本不足的形态必须回退，否则两三条数据就能翻转排序
  const thin = [mk('d1', 'refuted', 'binary', ['nuclei'])]
  const thinBoard = new CreditBoard({ halfLifeMs: 0, now: () => now })
  thinBoard.refresh(thin)
  check(
    'a thinly-sampled shape falls back to global',
    near(thinBoard.scoreOf('nuclei', 'binary').value, thinBoard.scoreOf('nuclei').value),
    { shape: thinBoard.scoreOf('nuclei', 'binary').value, global: thinBoard.scoreOf('nuclei').value },
  )
}

// ── 11. 形态级信誉真的会改注册表顺序
{
  const now = Date.now()
  const ev = { ref: 'e', pathKey: 'p', addedAt: 1, source: { kind: 'worker', taskId: 't', argv: ['nuclei'], cwd: '/' } }
  const mk = (id, status, shape, blame) => ({
    id, claim: id, status, evidence: [ev], independentPaths: 1, createdAt: now, updatedAt: now,
    ...(shape === undefined ? {} : { shape }),
    ...(blame === undefined ? {} : { blame }),
  })
  const claims = [
    mk('u1', 'confirmed', 'url'), mk('u2', 'confirmed', 'url'), mk('u3', 'confirmed', 'url'),
    mk('d1', 'refuted', 'directory', ['nuclei']),
    mk('d2', 'refuted', 'directory', ['nuclei']),
    mk('d3', 'refuted', 'directory', ['nuclei']),
  ]
  const board = new CreditBoard({ halfLifeMs: 0, now: () => now })
  board.refresh(claims)
  const reg = new AgentRegistry(DEFAULT_AGENTS)
  const creditOf = (id, shape) => board.scoreOf(id, shape).value
  const onUrl = reg.available('web-pentest', 'url', { creditOf }).map((c) => c.id)
  const onDir = reg.available('web-pentest', 'directory', { creditOf }).map((c) => c.id)
  check('nuclei is promoted on the shape it is good at', onUrl[0] === 'nuclei', onUrl)
  check('and demoted on the shape it fails at', onDir[0] !== 'nuclei', onDir)
  check('still present on the bad shape', onDir.includes('nuclei'), onDir)
}

// ── 12. 命中率通道：定论还没来时也能给方向
{
  const now = Date.now()
  const ev = (tool, strength) => ({
    ref: `e-${tool}-${strength}`,
    pathKey: `tool:${tool}:${strength}`,
    addedAt: 1,
    relevance: { strength, matched: [] },
    source: { kind: 'worker', taskId: 't', argv: [tool], cwd: '/' },
  })
  // 一条还没定论的 claim：只有相关性信号，没有 confirmed/refuted
  const open = (id, tool, strength) => ({
    id, claim: id, status: 'partial', evidence: [ev(tool, strength)], independentPaths: 1, createdAt: now, updatedAt: now,
  })
  const sharp = [open('s1', 'sharp', 'strong'), open('s2', 'sharp', 'strong'), open('s3', 'sharp', 'strong')]
  const blunt = [open('b1', 'blunt', 'weak'), open('b2', 'blunt', 'weak'), open('b3', 'blunt', 'weak')]
  const rel = tallyRelevance([...sharp, ...blunt], { now, halfLifeMs: 0 })
  check('strong relevance is counted', rel.get('sharp')?.strong === 3 && rel.get('sharp')?.weak === 0, rel.get('sharp'))
  check('weak relevance is counted', rel.get('blunt')?.weak === 3, rel.get('blunt'))

  const board = new CreditBoard({ halfLifeMs: 0, now: () => now })
  board.refresh([...sharp, ...blunt])
  const s = board.scoreOf('sharp')
  const b = board.scoreOf('blunt')
  check('relevance alone separates the two', s.value > b.value, { sharp: s.value, blunt: b.value })
  check('sharp sits above neutral', s.value > CREDIT_NEUTRAL, s.value)
  check('blunt sits below neutral', b.value < CREDIT_NEUTRAL, b.value)
  check('no settled verdict yet, but it still knows something', s.rawSample === 0 && s.strong > 0, s)
  check('basis names both channels', /accuracy/.test(s.basis) && /relevance/.test(s.basis), s.basis)

  // 没有相关性数据时不稀释准确率（否则一个什么都不知道的通道在投反对票）
  const settledOnly = creditScore({ agent: 'x', confirmed: 5, refuted: 0, runs: 5 }, 10, {})
  check('no relevance data means no dilution', near(settledOnly.posterior, 6 / 7), settledOnly.posterior)
  check('and the basis stays quiet about relevance', !/relevance/.test(settledOnly.basis), settledOnly.basis)

  // 手工证据（没有 relevance）不参与：不知道就当不知道
  const manual = {
    id: 'm', claim: 'm', status: 'partial', independentPaths: 1, createdAt: now, updatedAt: now,
    evidence: [{ ref: 'r', pathKey: 'p', addedAt: 1 }],
  }
  check('manual evidence has no relevance signal', tallyRelevance([manual], { now, halfLifeMs: 0 }).size === 0)

  // control 证据不算：它跑的是本地样本，不是这次的目标
  const controlled = {
    id: 'c', claim: 'c', status: 'partial', independentPaths: 1, createdAt: now, updatedAt: now,
    evidence: [{ ...ev('checksec', 'weak'), role: 'control' }],
  }
  check('calibration evidence is not relevance signal', tallyRelevance([controlled], { now, halfLifeMs: 0 }).size === 0)
}

// ── 13. 一轮之内也要学习：版本变了，查询时自动重算
{
  const now = Date.now()
  let version = 0
  let claims = []
  const board = new CreditBoard({
    halfLifeMs: 0,
    now: () => now,
    versionOf: () => version,
    fetchClaims: () => claims,
  })
  const ev = (tool) => ({
    ref: `e-${tool}`, pathKey: `tool:${tool}`, addedAt: 1,
    relevance: { strength: 'strong', matched: [] },
    source: { kind: 'worker', taskId: 't', argv: [tool], cwd: '/' },
  })
  const mk = (id, tool) => ({
    id, claim: id, status: 'partial', evidence: [ev(tool)], independentPaths: 1, createdAt: now, updatedAt: now,
  })
  claims = [mk('a', 'slow')]
  board.refresh(claims)
  const before = board.scoreOf('slow').value

  // 模拟「同一轮里又来了两条证据」：内容变了、版本号变了
  claims = [mk('a', 'slow'), mk('b', 'slow'), mk('c', 'slow')]
  version = 3
  const after = board.scoreOf('slow').value
  check('a version bump triggers a recompute on read', after > before, { before, after })
  check('the recompute used the new evidence', board.scoreOf('slow').strong === 3, board.scoreOf('slow').strong)

  // 版本没变就不该重算（同一份输入，同一个答案）
  const stable = board.scoreOf('slow').value
  check('no version change, same answer', board.scoreOf('slow').value === stable)
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exit(1)
