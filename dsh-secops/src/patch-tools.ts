/**
 * 补丁变体工具：把一次修复变成变异查询。
 *
 * 它不产出漏洞结论，产出的是**下一步该去哪找**。这个定位很重要：
 * 如果让工具直接说"这处也是漏洞"，那它就变成了又一个高误报的静态扫描器；
 * 而说"补丁在这里加了空值检查、汇点是 foo()，去找同样调用 foo() 但没有
 * 前置检查的地方"，这是一条人可以立刻验证的线索。
 */

import fs from 'node:fs'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import { analyzeFix } from './patch-variant.ts'

const PATTERN_SCHEMA = {
  type: 'object',
  properties: {
    found: { type: 'boolean' },
    kind: { type: 'string' },
    rationale: { type: 'string' },
    added_lines: { type: 'array', items: { type: 'string' } },
    signals: { type: 'array', items: { type: 'string' } },
    semgrep_rule: { type: 'string' },
    next_step: { type: 'string' },
  },
  required: ['found'],
} as const

export function patchTools(): ToolDefinition[] {
  const analyzeTool: ToolDefinition = {
    name: 'patch_analyze',
    description:
      'Turn a security fix into a variant query. Give the code BEFORE and AFTER the fix (as file paths or ' +
      'inline text); it extracts what kind of check the patch added (null guard / bounds check / sanitizer / ' +
      'auth guard / type check), the sink it protects, and generates a semgrep rule skeleton that finds call ' +
      'sites MISSING that same check elsewhere in the codebase. ' +
      'This is the cheapest route to finding a missed sibling: incomplete fixes are common, and a patch is a ' +
      'free specification of what to look for. It returns a lead, not a finding — confirm with oracle_run.',
    parameters: {
      type: 'object',
      properties: {
        before_path: { type: 'string', description: 'File containing the vulnerable version.' },
        after_path: { type: 'string', description: 'File containing the fixed version.' },
        before_text: { type: 'string', description: 'Inline vulnerable snippet (used when before_path is absent).' },
        after_text: { type: 'string', description: 'Inline fixed snippet (used when after_path is absent).' },
      },
    },
    output: {
      schema: PATTERN_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as Record<string, unknown>
      const read = (p: unknown): string | null => {
        if (typeof p !== 'string' || p === '') return null
        try {
          return fs.readFileSync(p, 'utf8')
        } catch {
          return null
        }
      }
      const before = read(a['before_path']) ?? (typeof a['before_text'] === 'string' ? a['before_text'] : null)
      const after = read(a['after_path']) ?? (typeof a['after_text'] === 'string' ? a['after_text'] : null)
      if (before === null || after === null) {
        return { found: false, next_step: 'provide both before and after (paths or inline text)' }
      }
      const pattern = await analyzeFix(before, after)
      if (pattern === null) {
        return { found: false, next_step: 'no added lines detected — are these really two versions of the same code?' }
      }
      return {
        found: true,
        kind: pattern.kind,
        rationale: pattern.rationale,
        added_lines: [...pattern.addedLines],
        signals: [...pattern.signals],
        semgrep_rule: pattern.semgrepRule,
        next_step:
          `run the generated rule against the repository, then pick the top hits and verify each with oracle_run; ` +
          `the ones that reproduce are missed siblings of the same fix`,
      }
    },
  }
  return [analyzeTool]
}
