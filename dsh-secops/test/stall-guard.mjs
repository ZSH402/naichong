import { StallDetector, stallReminder } from '../dist/stall-guard.js'
const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const d = new StallDetector({ window: 10, threshold: 4, cooldown: 5 })
// 四次同一操作的不同变体
for (let i = 0; i < 4; i += 1) d.record('bash', { command: `python3 brute.py --order ${i}` })
check('variants of one command count as the same action', d.inspect().stalled === true, d.inspect())
check('signature is the tool name', d.inspect().signature?.startsWith('bash'))

const d2 = new StallDetector({ window: 10, threshold: 4, cooldown: 5 })
for (const c of ['ls', 'cat a', 'grep b', 'python3 x', 'wc -l']) d2.record('bash', { command: c })
check('genuinely different commands are not a stall', d2.inspect().stalled === false, d2.inspect())

const d3 = new StallDetector({ window: 10, threshold: 3, cooldown: 100 })
for (let i = 0; i < 3; i += 1) d3.record('bash', { command: 'same' })
check('nudge fires on stall', d3.shouldNudge() !== undefined)
check('nudge cools down', d3.shouldNudge() === undefined)
check('stats count nudges', d3.stats().nudges === 1, d3.stats())

// 长十六进制串和长数字不该让同一操作看起来不同
const d4 = new StallDetector({ window: 10, threshold: 4 })
for (const h of ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32), 'd'.repeat(32)]) d4.record('bash', { command: `echo ${h}` })
check('variable hex does not mask a repeated action', d4.inspect().stalled === true, d4.inspect())

const text = stallReminder({ stalled: true, hits: 5, window: 12, signature: 'bash' })
check('reminder names the count', text.includes('12') && text.includes('5'), text)
check('reminder tells it to write the hypothesis down', text.includes('claim_assert'))
check('reminder does not scold', !/sorry|道歉|失败/.test(text))

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
