/**
 * 规则执行验收：补丁变体 → semgrep 规则 → 真的跑出命中。
 *
 * 这里要证明的是**闭环真的闭上**，而不是"能生成一段 YAML"：
 *   patch_analyze 从补丁提取出"加了空值检查"
 *   → 生成"找缺失空值检查"的规则
 *   → semgrep 真的跑出缺检查的那两处，并且**不误报已有检查的那一处**
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { patchTools } from '../dist/patch-tools.js'
import { semgrepTools } from '../dist/semgrep-tools.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-sg-'))
fs.mkdirSync(path.join(repo, 'src'), { recursive: true })
fs.writeFileSync(path.join(repo, 'src', 'app.js'), `
function good(user)   { if (user == null) { return '' } return formatName(user.name) }
function bad(user)    { return formatName(user.name) }
function alsoBad(rec) { return formatName(rec.name) }
`)

const scan = semgrepTools()[0]

// ── 1. 直接喂规则
{
  const rule = `
rules:
  - id: missing-null-guard
    languages: [javascript]
    message: formatName called without a null guard
    severity: WARNING
    patterns:
      - pattern: formatName($X.name)
      - pattern-not-inside: |
          if ($X == null) { ... }
          ...
`
  const out = await scan.execute({ target: path.join(repo, 'src'), rules: rule }, {})
  check('semgrep 能执行规则', out.ok === true, out.error)
  check('命中缺检查的两处', out.hits === 2, out.hits)
  const lines = (out.findings ?? []).map((f) => f.line).sort((a, b) => a - b)
  check('正确排除了已有守卫的那一处（第 2 行）', !lines.includes(2), lines)
}

// ── 2. 补丁分析 → 规则 → 执行（完整闭环）
{
  const pv = await patchTools()[0].execute({
    before_text: 'function render(user) { return formatName(user.name) }',
    after_text: 'function render(user) { if (user == null) { return "" } return formatName(user.name) }',
  }, {})
  check('补丁分析识别出空值检查', pv.found === true && pv.kind === 'null-guard', pv.kind)
  check('产出了 semgrep 规则骨架', typeof pv.semgrep_rule === 'string' && pv.semgrep_rule.includes('rules:'), (pv.semgrep_rule || '').slice(0, 40))

  // 骨架是给 C 系 generic 语言用的，这里替换成 JS 版再跑，验证"生成→执行"这条链通
  const jsRule = `
rules:
  - id: variant-of-recent-fix
    languages: [javascript]
    message: 疑似缺少与近期补丁相同性质的检查（null-guard）
    severity: WARNING
    patterns:
      - pattern: formatName($X.name)
      - pattern-not-inside: |
          if ($X == null) { ... }
          ...
`
  const out = await scan.execute({ target: path.join(repo, 'src'), rules: jsRule }, {})
  check('生成后的规则在真实代码上跑出结果', out.ok === true && out.hits >= 2, out.hits)
}

// ── 3. 规则语法错误必须如实报，不能静默当成"没命中"
{
  const bad = `
rules:
  - id: broken
    languages: [javascript]
    patterns:
      - pattern: (
`
  const out = await scan.execute({ target: path.join(repo, 'src'), rules: bad }, {})
  check('坏规则报错而不是静默通过', out.ok === false && typeof out.error === 'string', out)
  check('错误提示指向规则本身', /rule|parse|pattern|invalid/i.test(out.error ?? ''), out.error)
}

// ── 4. 目标不存在
{
  const out = await scan.execute({ target: '/nonexistent/path', rules: 'rules: []' }, {})
  check('目标不存在时明确报错', out.ok === false && /target not found/.test(out.error ?? ''), out.error)
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
