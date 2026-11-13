/**
 * 阶段 M 验收：Model Fallback。
 *
 * 重点不只测"能切"，更要测"不该切的时候不切"——
 * 把上下文超限或用户取消当成 provider 故障去切换，会把真实问题
 * 掩盖成"所有 provider 都失败"。
 */

import { ModelFallback, shouldFailover } from '../dist/model-fallback.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const routes = [
  { provider: 'deepseek-official', model: 'deepseek-flash' },
  { provider: 'backup-a', model: 'm1' },
  { provider: 'backup-b', model: 'm2' },
]

// ── 1. 判定：什么该切
{
  check('429 rate limit', shouldFailover({ message: 'x', code: 'RATE_LIMIT', status: 429 }) === true)
  check('500 server error', shouldFailover({ message: 'x', code: 'SERVER', status: 500 }) === true)
  check('503 unavailable', shouldFailover({ message: 'x', code: 'UNAVAILABLE', status: 503 }) === true)
  check('401 auth', shouldFailover({ message: 'x', code: 'AUTH', status: 401 }) === true)
  check('timeout by code', shouldFailover({ message: 'x', code: 'ETIMEDOUT' }) === true)
  check('socket reset', shouldFailover({ message: 'x', code: 'ECONNRESET' }) === true)
}

// ── 2. 判定：什么不该切（关键）
{
  check('context window', shouldFailover({ message: 'x', code: 'CONTEXT_WINDOW_EXCEEDED' }) === false)
  check('quota exhausted', shouldFailover({ message: 'x', code: 'QUOTA' }) === false)
  check('aborted', shouldFailover({ message: 'x', code: 'ABORTED' }) === false)
  check('refusal', shouldFailover({ message: 'x', code: 'REFUSAL' }) === false)
  check('400 bad request', shouldFailover({ message: 'x', code: 'BAD', status: 400 }) === false)
  check('404', shouldFailover({ message: 'x', code: 'NOT_FOUND', status: 404 }) === false)
}

// ── 3. 切换顺序与上限
{
  const f = new ModelFallback({ routes, maxSwitches: 2 })
  const fail = { message: 'boom', code: 'RATE_LIMIT', status: 429 }
  check('first failure switches', f.onRequestError('a1', fail) === true)
  check('route points to backup-a', f.routeFor('a1', routes[0])?.provider === 'backup-a', f.routeFor('a1', routes[0]))
  check('second failure switches again', f.onRequestError('a1', fail) === true)
  check('route points to backup-b', f.routeFor('a1', routes[0])?.provider === 'backup-b')
  check('third failure blocked by maxSwitches', f.onRequestError('a1', fail) === false)
  check('history records two switches', f.history().length === 2, f.history())
}

// ── 4. 用尽路由后不再切
{
  const f = new ModelFallback({ routes: routes.slice(0, 2), maxSwitches: 10 })
  const fail = { message: 'boom', code: 'RATE_LIMIT', status: 429 }
  check('switch once', f.onRequestError('a', fail) === true)
  check('no more routes', f.onRequestError('a', fail) === false)
}

// ── 5. 不该切的失败不会消耗切换额度
{
  const f = new ModelFallback({ routes })
  const noSwitch = { message: 'too long', code: 'CONTEXT_WINDOW_EXCEEDED' }
  check('non-failover failure ignored', f.onRequestError('a', noSwitch) === false)
  check('cursor untouched', f.snapshot().length === 1, f.snapshot())
  check('still on primary', f.routeFor('a', routes[0]) === undefined)
}

// ── 6. onSuccess 重置计数但不回退路由
{
  const f = new ModelFallback({ routes, maxSwitches: 1 })
  const fail = { message: 'boom', code: 'RATE_LIMIT', status: 429 }
  f.onRequestError('a', fail)
  check('switched once', f.snapshot()[0]?.switches === 1, f.snapshot())
  f.onSuccess('a')
  check('switch counter reset after success', f.snapshot()[0]?.switches === 0, f.snapshot())
  // 路由不回退：回到坏 provider 会再失败一轮，没必要
  check('route does not roll back', f.routeFor('a', routes[0])?.provider === 'backup-a', f.routeFor('a', routes[0]))
}

// ── 7. 单路由时完全不生效
{
  const f = new ModelFallback({ routes: [routes[0]] })
  check('single route is inert', f.enabled === false)
  check('never switches with one route', f.onRequestError('a', { message: 'x', code: 'RATE_LIMIT', status: 429 }) === false)
  check('routeFor returns undefined', f.routeFor('a', routes[0]) === undefined)
}

// ── 8. 多 agent 互不影响
{
  const f = new ModelFallback({ routes })
  const fail = { message: 'boom', code: 'RATE_LIMIT', status: 429 }
  f.onRequestError('agent-a', fail)
  check('agent-b unaffected', f.routeFor('agent-b', routes[0]) === undefined)
  check('agent-a switched', f.routeFor('agent-a', routes[0])?.provider === 'backup-a')
}

// ── 9. 自定义判定覆盖默认
{
  const f = new ModelFallback({ routes, shouldFailover: () => true })
  check('custom policy used', f.onRequestError('a', { message: 'x', code: 'CONTEXT_WINDOW_EXCEEDED' }) === true)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
