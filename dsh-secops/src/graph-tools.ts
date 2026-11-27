/**
 * 调用图工具：把 tree-sitter 建出来的图暴露给模型。
 *
 * 这一层的存在是因为**字符串搜索回答不了结构问题**。`rg` 能告诉你某个名字
 * 出现在哪几行，但回答不了"这个函数有没有调用方"（死代码不构成漏洞）、
 * "它的调用方又调用了什么"（切片该切到哪）。
 *
 * 实现走 python 子进程，因为它用的是 tree-sitter 的预编译语法包，
 * 而那套东西在 Python 生态里最成熟。TS 侧只负责调用与格式化——
 * 解析器不值得自己写，这是整份系统里最该借成熟件的地方之一。
 */

import { execFile } from 'node:child_process'
import path from 'node:path'
import { promisify } from 'node:util'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'

const execFileAsync = promisify(execFile)

export interface GraphToolsOptions {
  /** callgraph.py 的位置；不给就按仓库布局推断。 */
  readonly scriptPath?: string
  readonly pythonPath?: string
}

function defaultScript(): string {
  // 从插件目录往上找 engine/nav/callgraph.py
  const candidates = [
    process.env['NC_CALLGRAPH'],
    path.resolve(process.cwd(), 'engine/nav/callgraph.py'),
    path.resolve(process.cwd(), '../engine/nav/callgraph.py'),
    '/root/异构agent/engine/nav/callgraph.py',
  ]
  for (const c of candidates) {
    if (c === undefined || c === null || c === '') continue
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      if (require('node:fs').existsSync(c)) return c
    } catch {
      continue
    }
  }
  return ''
}

const RESULT_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    action: { type: 'string' },
    error: { type: 'string' },
    data: { type: 'object' },
  },
  required: ['ok', 'action'],
} as const

export function graphTools(opts: GraphToolsOptions = {}): ToolDefinition[] {
  const script = opts.scriptPath ?? defaultScript()
  const python = opts.pythonPath ?? 'python3'

  const tool: ToolDefinition = {
    name: 'call_graph',
    description:
      'Structural queries over a source tree, built with tree-sitter (multi-language). ' +
      'action="stats" gives function/edge counts and the most-called symbols; ' +
      'action="callers" tells you whether a symbol is reachable at all — NO CALLER strongly suggests the code a ' +
      'claim targets is dead, which usually means the claim cannot be triggered; ' +
      'action="slice" returns the N-hop neighbourhood of a symbol (callers and callees), which is the right ' +
      'amount of context to reason about one function — a whole file dilutes attention, a single function loses ' +
      'the caller contract that most false positives come from. ' +
      'Edges are matched by name, so common names (get/set/main) merge across classes; treat those as approximate.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['stats', 'callers', 'slice'] },
        root: { type: 'string', description: 'Source tree root.' },
        symbol: { type: 'string', description: 'Function/method name (required for callers and slice).' },
        hops: { type: 'number', description: 'Slice radius in call hops (default 2).' },
      },
      required: ['action', 'root'],
    },
    output: {
      schema: RESULT_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as { action?: string; root?: string; symbol?: string; hops?: number }
      const action = a.action ?? 'stats'
      if (script === '') {
        return { ok: false, action, error: 'callgraph.py not found; set NC_CALLGRAPH to its path' }
      }
      if (typeof a.root !== 'string' || a.root === '') {
        return { ok: false, action, error: 'root is required' }
      }
      const argv = [script, action, a.root]
      if (action === 'callers' || action === 'slice') {
        if (typeof a.symbol !== 'string' || a.symbol === '') {
          return { ok: false, action, error: `symbol is required for action="${action}"` }
        }
        argv.push(a.symbol)
      }
      if (action === 'slice') argv.push('--hops', String(a.hops ?? 2))
      try {
        const { stdout } = await execFileAsync(python, argv, { maxBuffer: 16 * 1024 * 1024, timeout: 180_000 })
        const data = JSON.parse(stdout.trim().split('\n').pop() ?? '{}') as Record<string, unknown>
        return { ok: true, action, data }
      } catch (err) {
        const e = err as { stderr?: string; message?: string }
        return { ok: false, action, error: (e.stderr ?? e.message ?? 'callgraph failed').slice(0, 500) }
      }
    },
  }

  return [tool]
}
