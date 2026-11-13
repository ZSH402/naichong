/**
 * 捷径拦截 + 答案闸门验收。
 *
 * 两个不变量：
 *   一、搜答案要能被认出来，且在两次之后被拒——不然换个 grep 写法就绕过了
 *   二、没有 confirmed claim 的答案，形式上就过不了闸门
 *
 * 第二条是重点：闸门**不判断答案对不对**（那是它做不到的事），
 * 只判断「有没有证据撑着」。假扮成能判对错的闸门比没有闸门更危险。
 */

import { detectShortcut, ShortcutGuard, shortcutWarning, DEFAULT_SHORTCUT_PATTERNS } from '../dist/shortcut-guard.js'
import { judgeAnswer } from '../dist/answer-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

// ── 1. 认出搜答案
{
  const should = [
    "grep -ril 'tpctf|flag' .",
    'grep -r "flag" /root/异构agent/ctf',
    'rg -l flag .',
    'grep -R answer src/',
    "find / -name '*flag*'",
    'find . -name "flag"',
    'strings booru.db | grep flag',
    'cat /flag',
    'head -c 100 flag.txt',
    'find workspace -name "*flag*"',
  ]
  for (const cmd of should) {
    check(`detects: ${cmd.slice(0, 40)}`, detectShortcut(cmd) !== undefined, cmd)
  }

  // 正常枚举不该被误伤——真实渗透里这些是合法侦察
  const shouldNot = [
    'ls -la /root/异构agent/ctf/superbooru/files',
    "grep -n 'flag_bin' implications.txt",
    'cat Dockerfile',
    'python3 solve.py',
    'nmap -sV 127.0.0.1',
    'find . -name "*.py"',
    'grep -r "password" /etc/app/config',
    'strings booru.db | head',
  ]
  for (const cmd of shouldNot) {
    check(`allows: ${cmd.slice(0, 40)}`, detectShortcut(cmd) === undefined, detectShortcut(cmd))
  }
}

// ── 2. 两次警告后拒绝
{
  const g = new ShortcutGuard({ warnTimes: 2, blockAfter: 2 })
  const a = g.inspect('grep -ril flag .')
  check('first hit warns', a.action === 'warn', a)
  const b = g.inspect("find . -name '*flag*'")
  check('second hit still warns', b.action === 'warn', b)
  const c = g.inspect('strings x | grep flag')
  check('third hit is denied', c.action === 'deny', c)
  check('stats count blocks', g.stats().blocks === 1, g.stats())
  check('stats break down by pattern', Object.keys(g.stats().byPattern).length >= 2, g.stats())

  const ok = g.inspect('ls -la')
  check('normal command still allowed after blocks', ok.action === 'allow')
}

// ── 3. 提醒说明「为什么路不成立」而不是「你不许」
{
  const hit = detectShortcut('grep -ril flag .')
  const text = shortcutWarning(hit, 1, false)
  check('warning explains why the shortcut fails', /不成立/.test(text))
  check('warning says an unproven answer is a guess', /无法证明|没有区别/.test(text))
  check('warning points at the right next action', text.includes('claim_assert'))
  check('warning does not scold', !/不许|严禁|违规/.test(text))

  const blocking = shortcutWarning(hit, 3, true)
  check('blocking variant says it will be denied', /拒绝/.test(blocking))
}

// ── 4. 答案闸门：没 claim 就是猜测
{
  const v = judgeAnswer(undefined)
  check('no claim means unverified', v.accepted === false && v.verdict === 'unverified', v)
  check('and says what is missing', v.missing.length > 0 && /guess/.test(v.missing[0]), v.missing)
}

// ── 5. 有 claim 但没定论
{
  const v = judgeAnswer({ claim: 'flag is X', status: 'hypothesis', independentPaths: 0, evidence: [] })
  check('hypothesis is not an answer', v.accepted === false, v)
  check('lists the status gap', v.missing.some((m) => /status/.test(m)), v.missing)
}

// ── 6. 只有一条独立路径也不行
{
  const v = judgeAnswer({ claim: 'flag is X', status: 'partial', independentPaths: 1, evidence: [{}, {}] })
  check('one path is not enough', v.accepted === false, v)
  check('names the path requirement', v.missing.some((m) => /independent path/.test(m)), v.missing)
}

// ── 7. 没有证据的 confirmed 也不行
{
  const v = judgeAnswer({ claim: 'flag is X', status: 'confirmed', independentPaths: 2, evidence: [] })
  check('confirmed without evidence is rejected', v.accepted === false, v)
  check('names the empty evidence', v.missing.some((m) => /no evidence/.test(m)), v.missing)
}

// ── 8. 满足条件才接受
{
  const v = judgeAnswer({ claim: 'flag is X', status: 'confirmed', independentPaths: 2, evidence: [{}, {}] })
  check('properly backed answer is accepted', v.accepted === true && v.verdict === 'established', v)
  check('no missing items when accepted', v.missing.length === 0, v.missing)
  check('threshold is configurable',
    judgeAnswer({ claim: 'x', status: 'confirmed', independentPaths: 2, evidence: [{}] }, { threshold: 3 }).accepted === false)
}

// ── 9. 默认模式覆盖常见写法，但不无限膨胀
{
  check('default patterns exist', DEFAULT_SHORTCUT_PATTERNS.length >= 4)
  check('every pattern carries a reason', DEFAULT_SHORTCUT_PATTERNS.every((p) => p.why.length > 10))
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
