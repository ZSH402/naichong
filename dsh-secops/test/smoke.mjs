/**
 * 行为冒烟测试：不依赖完整 DSH 运行时，只验证三道闸的实际判断结果。
 * 用最小的 ctx 桩替换 cordis 上下文，捕获注册进 tools.guard 的函数并直接调用。
 */

import { installScopeGuard, installBudgetGuard, extractTargets } from '../dist/guards.js'
import { installDecisionStage } from '../dist/decision.js'
import { resolveConfig } from '../dist/config.js'

const results = []
function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  results.push({ label, ok, actual })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`)
  if (!ok) console.log(`      actual=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
}

function makeCtx() {
  const guards = []
  const listeners = []
  return {
    guards,
    listeners,
    logger: { info() {}, warn() {} },
    tools: {
      guard(fn) {
        guards.push(fn)
        return () => {}
      },
    },
    on(name, fn) {
      listeners.push({ name, fn })
      return () => {}
    },
    // 决策阶段用 ctx.get 探测 projection 服务；桩实现即可。
    get(name) {
      if (name !== 'sessionProjections') return undefined
      return { register: async () => ({}), stateOf: () => undefined }
    },
  }
}

const config = resolveConfig({
  allowedHosts: ['Authorized.Example', '10.0.0.15'],
  maxToolCalls: 2,
  maxWallClockMs: 60_000,
  maxSteps: 2,
  logDecisions: false,
})

// ── 配置归一化
check('hosts lowercased+deduped', config.allowedHosts, ['authorized.example', '10.0.0.15'])

// ── 目标提取
check('extract url host', extractTargets('web_fetch', { url: 'https://a.example/x' }), ['a.example'])
check('extract from bash', extractTargets('bash', { command: 'curl https://b.example/y' }), ['b.example'])
check('non-url args yield none', extractTargets('bash', { command: 'ls -la' }), [])
check('null args yield none', extractTargets('bash', null), [])

// ── 范围闸
{
  const ctx = makeCtx()
  installScopeGuard(ctx, config)
  const guard = ctx.guards[0]
  check('in-scope allowed', guard({ name: 'web_fetch', arguments: { url: 'https://authorized.example/a' } }), undefined)
  const denied = guard({ name: 'web_fetch', arguments: { url: 'https://evil.example/a' } })
  check('out-of-scope denied', typeof denied === 'string' && denied.includes('outside the authorized scope'), true)
  check('ip allowlist works', guard({ name: 'web_fetch', arguments: { url: 'http://10.0.0.15:8080/' } }), undefined)
}

// ── 预算闸（工具调用计数）
{
  const ctx = makeCtx()
  installBudgetGuard(ctx, config)
  const guard = ctx.guards[0]
  check('call 1 allowed', guard({ name: 'bash', arguments: {} }), undefined)
  check('call 2 allowed', guard({ name: 'bash', arguments: {} }), undefined)
  const denied = guard({ name: 'bash', arguments: {} })
  check('call 3 denied', typeof denied === 'string' && denied.includes('budget exhausted'), true)
}

// ── 决策阶段（步数上限）
{
  const ctx = makeCtx()
  await installDecisionStage(ctx, config)
  const listener = ctx.listeners.find((l) => l.name === 'agent/pre-step')
  check('pre-step listener registered', listener !== undefined, true)

  const nextEnter = async () => ({ kind: 'enter', messages: [] })
  const payload = (step) => ({
    agent: { id: 'agent-1' },
    messages: [],
    turn: 1,
    step,
    signal: { aborted: false },
  })

  const step1 = await listener.fn(payload(1), nextEnter)
  check('step 1 enters', step1.kind, 'enter')

  const step3 = await listener.fn(payload(3), nextEnter)
  check('step 3 rejected by maxSteps=2', step3.kind, 'reject')

  const upstream = async () => ({ kind: 'reject' })
  const kept = await listener.fn(payload(1), upstream)
  check('upstream reject preserved', kept.kind, 'reject')
}

const failed = results.filter((r) => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
