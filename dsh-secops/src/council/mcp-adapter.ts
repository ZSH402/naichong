/**
 * MCP 执行体：把任意 MCP server 包成统一 adapter。
 *
 * 这层之前是空的，代价很直接：CyberStrikeAI 编译好了、rea 装好了、
 * hexstrike 登记了，全都停在「用不上」。注册表里标个 MISSING 不等于不可用，
 * 而是我们没实现驱动它的那一层。
 *
 * 一个 server 几十个工具，不能全塞进候选列表——那会让每个方向都挤满
 * 同源的包装工具。所以候选只声明「这个方向我用 server 的哪个工具」，
 * adapter 负责连、调、翻译。
 */

import type { TaskAdapter, TaskContract, TaskResult, AdapterContext } from './contract.ts'
import { McpStdioClient } from '../mcp-client.ts'
import type { McpCallResult, McpServerSpec } from '../mcp-client.ts'

export interface McpToolBinding {
  /** 要调用的 MCP 工具名。 */
  readonly tool: string
  /** 把任务契约翻译成该工具的参数。 */
  readonly args: (contract: TaskContract) => Record<string, unknown>
  /**
   * 从工具返回里读结论。
   *
   * 返回 undefined 表示「这次输出里没有可判定的结论」——那就如实报 inconclusive。
   * 编一个 found 出来比不判更糟：MCP 工具的输出格式各异，靠关键字猜必然出错。
   */
  readonly verdict?: (result: McpCallResult) => { readonly found: boolean; readonly detail?: string } | undefined
}

export interface McpAdapterOptions {
  readonly spec: McpServerSpec
  /**
   * 候选 id → 该候选要用 server 的哪个工具。
   *
   * 一个 server 几十个工具，候选只声明「我这个方向用哪个」。按 id 查表，
   * 比按 kind 猜可靠——同 kind 下多个候选指向同一 server 的不同工具是常态。
   */
  readonly bindings: ReadonlyMap<string, McpToolBinding>
  /** 找不到对应候选时兜底用的工具（通常是 server 的通用执行器）。 */
  readonly fallback?: McpToolBinding
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
}

/**
 * 同一进程里复用连接。
 *
 * MCP server 启动要几百毫秒到几秒（CyberStrikeAI 是 22MB 的 Go 二进制），
 * 每次派活重启一个既慢又占内存。按 command 串做 key 缓存。
 */
const pool = new Map<string, McpStdioClient>()

function keyOf(spec: McpServerSpec): string {
  return `${spec.command.join('\u0000')}|${spec.cwd ?? ''}`
}

async function clientFor(spec: McpServerSpec): Promise<McpStdioClient> {
  const key = keyOf(spec)
  const existing = pool.get(key)
  if (existing !== undefined) return existing
  const client = new McpStdioClient(spec)
  await client.connect()
  pool.set(key, client)
  return client
}

/** 关闭所有缓存连接（插件卸载时调用）。 */
export function closeAllMcpClients(): void {
  for (const client of pool.values()) client.close()
  pool.clear()
}

export function createMcpAdapter(options: McpAdapterOptions): TaskAdapter {
  return {
    kind: 'mcp',
    describe: `MCP server（${options.spec.command[0] ?? '?'}），${String(options.bindings.size)} 个工具绑定`,
    async execute(contract: TaskContract, ctx: AdapterContext): Promise<TaskResult> {
      const startedAt = Date.now()
      const binding = options.bindings.get(contract.agentId ?? '') ?? options.fallback
      if (binding === undefined) {
        return {
          contract,
          outcome: 'refused',
          reason: `no MCP tool bound for "${contract.agentId ?? 'unknown'}"`,
          durationMs: 0,
          cost: 0,
        }
      }
      if (ctx.signal.aborted) {
        return { contract, outcome: 'failed', reason: 'aborted', durationMs: 0, cost: 0 }
      }

      let client: McpStdioClient
      try {
        client = await clientFor(options.spec)
      } catch (error) {
        return {
          contract,
          outcome: 'failed',
          reason: `mcp connect failed: ${String(error)}`,
          durationMs: Date.now() - startedAt,
          cost: 0,
        }
      }

      let result: McpCallResult
      try {
        result = await client.callTool(binding.tool, binding.args(contract))
      } catch (error) {
        // 连接断了就把缓存清掉，下次重连——否则后续每次派活都在一个死连接上失败。
        pool.delete(keyOf(options.spec))
        client.close()
        return {
          contract,
          outcome: 'failed',
          reason: `mcp call failed: ${String(error)}`,
          durationMs: Date.now() - startedAt,
          cost: 0,
        }
      }

      if (result.isError) {
        return {
          contract,
          outcome: 'failed',
          reason: `tool returned isError: ${result.text.slice(0, 200)}`,
          durationMs: Date.now() - startedAt,
          cost: contract.estimatedCost,
        }
      }

      const verdict = binding.verdict?.(result)
      if (verdict === undefined) {
        // 跑通了但这类工具的输出没有统一判据。如实说不知道，不猜。
        return {
          contract,
          outcome: 'inconclusive',
          reason: `${binding.tool} produced output without a structured verdict`,
          detail: result.text.slice(0, 300),
          durationMs: Date.now() - startedAt,
          cost: contract.estimatedCost,
        }
      }

      return {
        contract,
        outcome: 'settled',
        found: verdict.found,
        ...(verdict.detail === undefined ? {} : { detail: verdict.detail }),
        durationMs: Date.now() - startedAt,
        cost: contract.estimatedCost,
      }
    },
  }
}
