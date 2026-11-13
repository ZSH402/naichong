/**
 * 外部指导注入验收。
 *
 * 两个不变量：**只注入一次**（不能每轮都重放同一句），
 * 以及**消费原子**（读到半个文件比读不到更糟）。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { consumeGuidance, pushGuidance, GUIDANCE_FILENAME } from '../dist/guidance.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-guid-'))
const file = path.join(dir, GUIDANCE_FILENAME)

// ── 1. 没有文件时什么都不返回
check('missing file yields nothing', consumeGuidance(file).length === 0)

// ── 2. 推一条，消费一次
pushGuidance(file, '换个方法，别在枚举上耗')
const first = consumeGuidance(file)
check('pending guidance is delivered', first.length === 1 && first[0].includes('换个方法'), first)
check('delivered only once', consumeGuidance(file).length === 0)
check('file is removed after consume', !fs.existsSync(file))

// ── 3. 多条按行，空行和注释忽略
pushGuidance(file, '第一句')
fs.appendFileSync(file, '\n\n# 这是注释\n第二句\n')
const lines = consumeGuidance(file)
check('multiple lines delivered in order', lines.length === 2 && lines[0] === '第一句' && lines[1] === '第二句', lines)
check('comments and blanks skipped', !lines.some((l) => l.startsWith('#')), lines)

// ── 4. 消费不留下临时文件
pushGuidance(file, 'x')
consumeGuidance(file)
const leftovers = fs.readdirSync(dir).filter((f) => f.includes('.guidance.'))
check('no staging files left behind', leftovers.length === 0, leftovers)

// ── 5. 目录不存在时 push 会创建
const nested = path.join(dir, 'a', 'b', GUIDANCE_FILENAME)
pushGuidance(nested, 'deep')
check('push creates the directory', consumeGuidance(nested).length === 1)

// ── 6. 空白不产生空消息
pushGuidance(file, '   ')
check('whitespace-only guidance is dropped', consumeGuidance(file).length === 0)

fs.rmSync(dir, { recursive: true, force: true })
const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
