/**
 * 混合执行工具：编译插桩、覆盖率引导 fuzz、约束求解。
 *
 * ## 为什么这三件事凑在一起
 *
 * 它们是同一个问题的三个侧面：**目标里有一条你走不到的分支**。
 *
 *   插桩     —— 让你看得见走没走到（gcov 行覆盖 + ASan 崩溃判定）
 *   fuzz     —— 靠变异和覆盖反馈去撞那条分支
 *   solve    —— 条件明确时直接算出来，不用撞
 *
 * 单用任何一个都有明显短板：只看代码不知道能不能到；fuzz 撞不过魔数和校验和；
 * 求解需要把条件形式化。所以实际策略是"先算，算不出来再撞，撞的时候有反馈"。
 *
 * ## 为什么自己实现而不是调 afl
 *
 * 这台机器上没有 afl，也不适合为了让一个工具跑起来去装一套编译器和内核模块。
 * gcc 的 `--coverage` 就是 AFL 的 gcov 模式用的同一套插桩，核心循环只有
 * 变异-执行-看增量三步。差异要说清楚：**gcov 的粒度是行不是边**，反馈比
 * AFL 粗一档，长条件链的能力弱。所以它的定位是"能找到浅层缺陷"，
 * 不是替代专业 fuzzer。
 */

import { execFile } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { promisify } from 'node:util'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'

const execFileAsync = promisify(execFile)

export interface FuzzToolsOptions {
  readonly scriptPath?: string
  readonly pythonPath?: string
}

function defaultScript(): string {
  const candidates = [
    process.env['NC_FUZZLAB'],
    path.resolve(process.cwd(), 'engine/fuzz/fuzzlab.py'),
    path.resolve(process.cwd(), '../engine/fuzz/fuzzlab.py'),
    '/root/异构agent/engine/fuzz/fuzzlab.py',
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

export function fuzzTools(opts: FuzzToolsOptions = {}): ToolDefinition[] {
  const script = opts.scriptPath ?? defaultScript()
  const python = opts.pythonPath ?? 'python3'

  const call = async (args: string[]): Promise<{ ok: boolean; action: string; data?: Record<string, unknown>; error?: string }> => {
    try {
      const { stdout } = await execFileAsync(python, [script, ...args], {
        maxBuffer: 16 * 1024 * 1024,
        timeout: 600_000,
      })
      const data = JSON.parse(stdout.trim().split('\n').pop() ?? '{}') as Record<string, unknown>
      return { ok: data['ok'] === true, action: args[0] ?? '', data }
    } catch (err) {
      const e = err as { stderr?: string; message?: string; stdout?: string }
      // 脚本自己会把错误打成 JSON 输出，优先用它的
      if (typeof e.stdout === 'string' && e.stdout.trim() !== '') {
        try {
          const data = JSON.parse(e.stdout.trim().split('\n').pop() ?? '{}') as Record<string, unknown>
          return { ok: data['ok'] === true, action: args[0] ?? '', data }
        } catch {
          /* 落到下面 */
        }
      }
      return { ok: false, action: args[0] ?? '', error: (e.stderr ?? e.message ?? 'fuzzlab failed').slice(0, 500) }
    }
  }

  const tool: ToolDefinition = {
    name: 'fuzz_lab',
    description:
      'Compile-instrument, coverage-guided fuzz, and constraint-solve a native target. Three actions:\n' +
      '  build  — compile a C/C++ source with AddressSanitizer AND gcov coverage. ASan turns silent ' +
      'out-of-bounds reads into deterministic aborts, so "did not crash" stops meaning "is fine".\n' +
      '  fuzz   — coverage-guided loop: mutate a seed, run it, keep it only if it reached lines never ' +
      'reached before. Any crash is saved next to the binary so it can be replayed. Note the feedback ' +
      'granularity is gcov LINES, not edges like AFL — good enough for shallow defects, weaker on long ' +
      'condition chains.\n' +
      '  solve  — give z3 a set of constraints that express a check you believe is blocking the path, and ' +
      'it returns a satisfying assignment to try. Use this BEFORE fuzzing when the condition is explicit ' +
      '(length, magic value, checksum relationship): computing a value beats guessing one.\n' +
      'Reporting discipline: "no crash in N executions" is never evidence of safety — it only means those ' +
      'executions missed.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['build', 'fuzz', 'solve'] },
        source: { type: 'string', description: 'build: source file path.' },
        out: { type: 'string', description: 'build: output binary path.' },
        binary: { type: 'string', description: 'fuzz: instrumented binary path.' },
        source_name: { type: 'string', description: 'fuzz: source file NAME (not path) for gcov, e.g. target.c.' },
        mode: { type: 'string', enum: ['argv', 'stdin'], description: 'fuzz: how the input is fed (default stdin).' },
        iterations: { type: 'number', description: 'fuzz: max executions (default 300).' },
        time_budget: { type: 'number', description: 'fuzz: wall-clock budget in seconds (default 60).' },
        seed_dir: { type: 'string', description: 'fuzz: directory of seed inputs.' },
        constraints: {
          type: 'array',
          items: { type: 'string' },
          description: 'solve: Python expressions over x, y, z, e.g. ["x > 100", "x % 7 == 0"].',
        },
        no_asan: { type: 'boolean', description: 'build: disable AddressSanitizer (not recommended).' },
      },
      required: ['action'],
    },
    output: {
      schema: RESULT_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as Record<string, unknown>
      const action = typeof a['action'] === 'string' ? a['action'] : ''
      if (script === '') {
        return { ok: false, action, error: 'fuzzlab.py not found; set NC_FUZZLAB to its path' }
      }

      if (action === 'build') {
        const src = typeof a['source'] === 'string' ? a['source'] : ''
        const out = typeof a['out'] === 'string' ? a['out'] : ''
        if (src === '' || out === '') return { ok: false, action, error: 'source and out are required' }
        const argv = ['build', src, '-o', out]
        if (a['no_asan'] === true) argv.push('--no-asan')
        return call(argv)
      }

      if (action === 'fuzz') {
        const bin = typeof a['binary'] === 'string' ? a['binary'] : ''
        const srcName = typeof a['source_name'] === 'string' ? a['source_name'] : ''
        if (bin === '' || srcName === '') {
          return { ok: false, action, error: 'binary and source_name are required for fuzz' }
        }
        const argv = [
          'fuzz', bin, '--source', srcName,
          '--iterations', String(typeof a['iterations'] === 'number' ? a['iterations'] : 300),
          '--time-budget', String(typeof a['time_budget'] === 'number' ? a['time_budget'] : 60),
          '--mode', typeof a['mode'] === 'string' ? a['mode'] : 'stdin',
        ]
        if (typeof a['seed_dir'] === 'string' && a['seed_dir'] !== '') argv.push('--seed-dir', a['seed_dir'])
        return call(argv)
      }

      if (action === 'solve') {
        const cs = Array.isArray(a['constraints'])
          ? (a['constraints'] as unknown[]).filter((x): x is string => typeof x === 'string')
          : []
        if (cs.length === 0) return { ok: false, action, error: 'constraints array is required' }
        return call(['solve', ...cs])
      }

      return { ok: false, action, error: `unknown action: ${action}` }
    },
  }

  return [tool]
}
