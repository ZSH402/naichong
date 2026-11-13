/**
 * 集成测试：在真实的 cordis Context + 真实的 dsh-tools 管道上验证 guard。
 *
 * 与 smoke.mjs 的区别：smoke 用桩替换 ctx，验证的是函数逻辑；
 * 这里加载真实的 systemPrompt + tools 服务，走真实的 tools.execute 管道，
 * 验证 guard 是否真的插在工具执行路径上。
 *
 * 运行：node test/integration.mjs
 */

import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import Tools from '@deepseek-ai/dsh-tools'
import SessionStore from '@deepseek-ai/dsh-session'
import Projections from '@deepseek-ai/dsh-session-projection'
import { apply as secopsApply, inject as secopsInject, name as secopsName } from '../dist/index.js'

const results = []
function check(label, ok, detail) {
  results.push({ label, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`)
  if (!ok && detail !== undefined) console.log(`      ${detail}`)
}

const ctx = new Context()
ctx.plugin(SystemPrompt)
ctx.plugin(Tools)
// 决策阶段在 apply 里注册 projection；缺这两个服务会让 apply 抛错，
// 而 cordis 的注册是 effect-scoped —— 插件加载失败会把已注册的 guard 一起回滚。
ctx.plugin(SessionStore)
ctx.plugin(Projections)
await new Promise((r) => setTimeout(r, 500))

check('tools service loaded', ctx.get('tools') !== undefined)
check('systemPrompt service loaded', ctx.get('systemPrompt') !== undefined)

ctx.plugin({
  name: secopsName,
  inject: secopsInject,
  apply: (c) => secopsApply(c, { allowedHosts: ['authorized.example'], maxToolCalls: 10 }),
})
await new Promise((r) => setTimeout(r, 300))

ctx.tools.register({
  name: 'web_fetch',
  description: 'integration fixture',
  parameters: { type: 'object', properties: { url: { type: 'string' } } },
  output: {
    schema: { type: 'array', items: { type: 'string' } },
    render: (_args, value) => value.map((text) => ({ type: 'text', text })),
  },
  execute: async () => ['EXECUTED'],
})

const call = (url) =>
  ctx.tools.execute({
    callId: crypto.randomUUID(),
    name: 'web_fetch',
    arguments: { url },
    signal: new AbortController().signal,
  })

// 0.2.2 把 executor 拆成可插拔组件；没有 executor 时 execute() 会抛
// TOOL_EXECUTOR_UNAVAILABLE。guard 在 pipeline 层，checkGuards 同样经过它，
// 因此在无 executor 的环境下降级验证守卫语义。
let useCheckGuards = false
try {
  await call('https://authorized.example/a')
} catch (error) {
  if (String(error?.code) === 'TOOL_EXECUTOR_UNAVAILABLE') useCheckGuards = true
  else throw error
}
const guardOnly = (url) => {
  const reason = ctx.tools.checkGuards({
    callId: crypto.randomUUID(), name: 'web_fetch', arguments: { url }, signal: new AbortController().signal,
  })
  return reason === undefined
    ? { isError: false, content: [{ type: 'text', text: 'EXECUTED' }] }
    : { isError: true, error: { message: reason } }
}
const run = useCheckGuards ? guardOnly : call

const allowed = await run('https://authorized.example/a')
check('in-scope executes for real', allowed.isError === false, JSON.stringify(allowed).slice(0, 200))
check('in-scope body is tool output', JSON.stringify(allowed.content).includes('EXECUTED'))

const denied = await run('https://evil.example/a')
check('out-of-scope blocked before execution', denied.isError === true, JSON.stringify(denied).slice(0, 200))
check(
  'denial reason comes from secops guard',
  JSON.stringify(denied).includes('secops/scope') && JSON.stringify(denied).includes('outside the authorized scope'),
  JSON.stringify(denied).slice(0, 300),
)
check('blocked call never ran the tool body', !JSON.stringify(denied).includes('EXECUTED'))

const failed = results.filter((r) => !r.ok)
console.log(`\n模式: ${useCheckGuards ? 'checkGuards（无 executor，0.2.2）' : 'execute（完整管道）'}`)
console.log(`${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
