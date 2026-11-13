/**
 * 时间信用验收。
 *
 * 核心不变量：**时间是挣来的，不是给的**。
 * 每个断言都在防一种「时间被刷走」的方式：
 *   - 模型自称有进展 → 不算，必须过 ClaimStore 的校验
 *   - 同一件事反复请款 → 只记一次
 *   - 连着交证据刷冷却 → 冷却期内不发放
 *   - 无上限续命 → 触顶即停
 */

import { TimeCredit, msToHuman, DEFAULT_TIME_CREDIT } from '../dist/time-credit.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const MIN = 60 * 1000

// ── 1. 基础额度与计时
{
  let now = 1000
  const c = new TimeCredit({ baseMs: 30 * MIN, grantMs: 10 * MIN, maxMs: 120 * MIN, grantCooldownMs: 2 * MIN }, { now: () => now })
  check('not started means full base available', c.remaining() === 30 * MIN)
  check('not started is not expired', c.expired() === false)

  c.start()
  now += 10 * MIN
  check('time spent reduces remaining', c.remaining() === 20 * MIN, c.remaining())
  now += 20 * MIN
  check('expires when base runs out', c.expired() === true)
}

// ── 2. 进展续期
{
  let now = 0
  const c = new TimeCredit({ baseMs: 30 * MIN, grantMs: 10 * MIN, maxMs: 120 * MIN, grantCooldownMs: 2 * MIN }, { now: () => now })
  c.start()
  now += 25 * MIN

  const g1 = c.grant('hypothesis', 'claim-1', 'test')
  check('first progress grants time', g1.granted === true && g1.amount === 10 * MIN, g1)
  check('remaining grows after grant', c.remaining() === 15 * MIN, c.remaining())
}

// ── 3. 同一件事不重复请款
{
  let now = 0
  const c = new TimeCredit({ grantCooldownMs: 0 }, { now: () => now })
  c.start()
  check('first grant ok', c.grant('strong-evidence', 'c1', 'e1').granted === true)
  now += MIN
  const again = c.grant('strong-evidence', 'c1', 'e2')
  check('same kind on same claim is not credited twice', again.granted === false, again)
  check('reason names the duplicate', /already credited/.test(again.reason), again.reason)

  const other = c.grant('strong-evidence', 'c2', 'e3')
  check('a different claim is a different progress', other.granted === true, other)
}

// ── 4. 冷却期内不发放，但记下这件事
{
  let now = 0
  const c = new TimeCredit({ grantCooldownMs: 2 * MIN, maxMs: 120 * MIN }, { now: () => now })
  c.start()
  check('start ok', c.grant('hypothesis', 'a', 'x').granted === true)
  now += 1000
  const second = c.grant('strong-evidence', 'b', 'y')
  check('cooldown blocks the second grant', second.granted === false, second)
  check('cooldown reason is explicit', /cooldown/.test(second.reason), second.reason)

  now += 3 * MIN
  const third = c.grant('strong-evidence', 'b', 'y')
  check('after cooldown the same progress still counts', third.granted === true, third)
}

// ── 5. 上限
{
  let now = 0
  const c = new TimeCredit({ baseMs: 30 * MIN, grantMs: 60 * MIN, maxMs: 60 * MIN, grantCooldownMs: 0 }, { now: () => now })
  c.start()
  const a = c.grant('hypothesis', 'a', 'x')
  check('grant is clipped to the cap', a.granted === true && a.amount === 30 * MIN, a)
  now += MIN
  const b = c.grant('strong-evidence', 'b', 'y')
  check('cap reached stops further grants', b.granted === false && /cap/.test(b.reason), b)
  check('total never exceeds the cap', c.view().total === 60 * MIN, c.view().total)
}

// ── 6. 收尾提醒只发一次
{
  let now = 0
  const c = new TimeCredit({ baseMs: 30 * MIN, warnAtMs: 5 * MIN }, { now: () => now })
  c.start()
  now += 20 * MIN
  check('no warning while comfortable', c.shouldWarn() === false)
  now += 7 * MIN // 剩 3 分钟
  check('warning fires near the end', c.shouldWarn() === true)
  check('warning does not repeat', c.shouldWarn() === false)
}

// ── 7. 进度事件是唯一入口：没有 claim 动作就没有续期
{
  let now = 0
  const c = new TimeCredit({ baseMs: 30 * MIN }, { now: () => now })
  c.start()
  now += 30 * MIN
  check('running out of time without progress expires', c.expired() === true)
  check('expired view reports zero remaining', c.view().remaining === 0)
}

// ── 8. 账本
{
  let now = 0
  const c = new TimeCredit({ grantCooldownMs: 0 }, { now: () => now })
  c.start()
  c.grant('hypothesis', 'a', 'stmt')
  now += MIN
  c.grant('refutation', 'b', 'dead end')
  const v = c.view()
  check('ledger records each grant', v.grants.length === 2, v.grants.length)
  check('ledger carries the reason kinds', v.grants.map((g) => g.kind).join(',') === 'hypothesis,refutation')
  check('ledger exposes base and granted separately', v.base === 30 * MIN && v.granted === 20 * MIN, v)
}

// ── 9. 人可读时间
{
  check('msToHuman seconds', msToHuman(45_000) === '45s', msToHuman(45_000))
  check('msToHuman minutes', msToHuman(30 * MIN) === '30m', msToHuman(30 * MIN))
  check('msToHuman mixed', msToHuman(5 * MIN + 20_000) === '5m20s', msToHuman(5 * MIN + 20_000))
  check('msToHuman zero', msToHuman(0) === '0s')
}

// ── 10. 默认值
{
  check('default base is 30 minutes', DEFAULT_TIME_CREDIT.baseMs === 30 * MIN)
  check('default grant is 10 minutes', DEFAULT_TIME_CREDIT.grantMs === 10 * MIN)
  check('default cap is above base', DEFAULT_TIME_CREDIT.maxMs > DEFAULT_TIME_CREDIT.baseMs)
}

// ── 扣减：惩罚这一半
{
  let now = 0
  const c = new TimeCredit({}, { now: () => now })
  c.start(0)
  // 没开始计时之前不扣
  const fresh = new TimeCredit({}, { now: () => 0 })
  check('debit before start is refused', fresh.debit('stall', 'x').granted === false)

  now = MIN
  const first = c.debit('stall', '3 similar calls')
  check('stall charges time', first.granted === true && first.amount === -DEFAULT_TIME_CREDIT.debitMs, first)
  check('remaining drops by the charge', first.remaining === 30 * MIN - MIN - 5 * MIN, first.remaining)

  // 冷却期内不重复扣
  now = MIN + MIN
  check('cooldown blocks a second charge', c.debit('stall', 'again').granted === false)

  // 冷却过后可以再扣，但总额有上限
  now = MIN + 6 * MIN
  const second = c.debit('repeat-approach', 'search script')
  check('charge resumes after cooldown', second.granted === true, second)

  now += 6 * MIN
  const third = c.debit('stall', 'again')
  check('third charge fills the cap', third.granted === true, third)
  now += 6 * MIN
  const fourth = c.debit('stall', 'again and again')
  check('cap stops further charges', fourth.granted === false && /cap/.test(fourth.reason), fourth)
  check('total debited equals the cap', c.debited === DEFAULT_TIME_CREDIT.maxDebitMs, c.debited)

  // 额度确实变少了，且不会扣成负数
  const v = c.view(now)
  check('view exposes the debited total', v.debited === DEFAULT_TIME_CREDIT.maxDebitMs, v.debited)
  check('allowance reflects the charge', v.total === 30 * MIN - DEFAULT_TIME_CREDIT.maxDebitMs, v.total)
  check('charges are written to the ledger as negatives', v.grants.filter((g) => g.amount < 0).length >= 3, v.grants)

  // 扣成负数要夹到 0，而不是给一段负额度
  const tiny = new TimeCredit({ baseMs: 60_000, maxDebitMs: 999_999_999, debitMs: 999_999_999 }, { now: () => 0 })
  tiny.start(0)
  tiny.debit('stall', 'x')
  check('allowance never goes negative', tiny.view(0).total === 0, tiny.view(0).total)
  check('spending past zero means expired', tiny.expired(1 * MIN) === true)

  // 关掉惩罚：maxDebitMs 0
  const noPenalty = new TimeCredit({ maxDebitMs: 0 }, { now: () => 0 })
  noPenalty.start(0)
  check('maxDebitMs 0 disables the penalty half', noPenalty.debit('stall', 'x').granted === false)
  check('and leaves the allowance untouched', noPenalty.view(MIN).total === DEFAULT_TIME_CREDIT.baseMs)
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
