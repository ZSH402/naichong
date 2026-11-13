/**
 * 两道 guard。都是同步的 —— ctx.tools.guard() 的签名是
 * `(exec: Readonly<ToolExecution>) => string | undefined`，
 * 返回非空字符串即拒绝，且单调：没有任何 guard 能 force-allow 另一个 guard 的拒绝。
 *
 * 因此这两道闸的生效不依赖插件加载顺序，也不依赖任何提示词。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { ToolGuard } from '@deepseek-ai/dsh-tools'
import type { ResolvedConfig } from './config.ts'

/**
 * 从一次工具调用里尽可能提取目标主机。
 *
 * 这是一次**静态文本提取**，不是解析器：guard 是同步的，不能做 DNS 解析、
 * 不能跟随重定向、不能看实际连接地址。它的价值是拦住"明显越界"的调用，
 * 真正的强制必须在网络层（SandboxProvider 的 netns/egress proxy）。
 *
 * 解析不出来时返回空数组 —— 调用放行，但由 budget guard 的计数兜底，
 * 并且 extractTargets 的保守性要在使用文档里写清。
 */
export function extractTargets(toolName: string, args: unknown): string[] {
  if (typeof args !== 'object' || args === null) return []
  const record = args as Record<string, unknown>
  const hosts = new Set<string>()

  const pushUrl = (value: unknown): void => {
    if (typeof value !== 'string') return
    for (const match of value.matchAll(/https?:\/\/([^/\s:'"]+)/gi)) {
      const host = match[1]?.toLowerCase()
      if (host !== undefined && host.length > 0) hosts.add(host)
    }
  }

  // URL 形态的参数：web_fetch / web_search / 各类 fetch 工具。
  for (const key of ['url', 'uri', 'endpoint', 'target', 'host']) pushUrl(record[key])

  // bash 类工具：命令文本里的所有 URL。裸域名与 IP 不提取 —— 误判率太高，
  // 宁可放行并计数，也不要把 `ls -la` 误判成外联。
  for (const key of ['command', 'cmd', 'script']) {
    const value = record[key]
    if (typeof value === 'string') pushUrl(value)
  }

  void toolName
  return [...hosts]
}

export function installScopeGuard(ctx: Context, config: ResolvedConfig): void {
  if (config.allowedHosts.length === 0) {
    ctx.logger.info('secops: allowedHosts is empty — scope guard is inert')
    return
  }
  const allowed = new Set(config.allowedHosts)

  const guard: ToolGuard = (exec) => {
    // 只对可能在网络上出站的工具做判断；文件类工具由 workspace 沙箱管。
    const targets = extractTargets(exec.name, exec.arguments)
    for (const host of targets) {
      if (!allowed.has(host)) {
        return (
          `[secops/scope] target "${host}" is outside the authorized scope ` +
          `(allowed: ${[...allowed].join(', ')})`
        )
      }
    }
    return undefined
  }

  ctx.tools.guard(guard)
  ctx.logger.info(`secops: scope guard armed for ${config.allowedHosts.length} host(s)`)
}

/**
 * 工具封锁：整类能力直接拒绝。
 *
 * 与范围闸的区别：范围闸看目标主机，需要参数里带 URL；模型自己写的搜索词
 * 是自然语言，从里面抠不出主机。所以「不许联网找答案」这件事不能靠范围闸，
 * 必须按工具名封——在能力层面没有这个东西，比在提示里说「不要搜」可靠。
 */
export function installToolDenyGuard(ctx: Context, denied: readonly string[]): void {
  if (denied.length === 0) return
  const deny = new Set(denied)
  ctx.tools.guard((exec) => {
    if (!deny.has(exec.name)) return undefined
    return `[secops/denylist] tool "${exec.name}" is disabled for this profile`
  })
  ctx.logger.info(`secops: denied tools: ${[...deny].join(', ')}`)
}

export function installBudgetGuard(ctx: Context, config: ResolvedConfig): void {
  if (config.maxToolCalls === undefined && config.maxWallClockMs === undefined) {
    ctx.logger.info('secops: no budget configured — budget guard is inert')
    return
  }

  const startedAt = Date.now()
  let calls = 0

  const guard: ToolGuard = (exec) => {
    calls += 1

    if (config.maxToolCalls !== undefined && calls > config.maxToolCalls) {
      return `[secops/budget] tool-call budget exhausted (${calls} > ${config.maxToolCalls})`
    }

    if (config.maxWallClockMs !== undefined) {
      const elapsed = Date.now() - startedAt
      if (elapsed > config.maxWallClockMs) {
        return `[secops/budget] wall-clock budget exhausted (${elapsed}ms > ${config.maxWallClockMs}ms)`
      }
    }

    void exec
    return undefined
  }

  ctx.tools.guard(guard)
  ctx.logger.info(
    `secops: budget guard armed (maxToolCalls=${config.maxToolCalls ?? '∞'}, ` +
      `maxWallClockMs=${config.maxWallClockMs ?? '∞'})`,
  )
}
