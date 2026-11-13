/**
 * 决策审计工具：把决策过程的质量暴露给模型和人。
 *
 * 为什么要暴露给模型：它看不到自己的决策模式。连续三次同样理由的拒绝，
 * 在单轮上下文里是正常的，在审计视角下是卡死。让它看见自己的分数，
 * 比在提示词里写"不要重复"有效。
 */

import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { DecisionPolicy } from './decision-policy.ts'

const AUDIT_SCHEMA = {
  type: 'object',
  properties: {
    total: { type: 'number' },
    entered: { type: 'number' },
    rejected: { type: 'number' },
    emptyReasons: { type: 'number' },
    worstRepeat: { type: 'number' },
    worstStall: { type: 'number' },
    verdict: { type: 'string' },
    violations: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          code: { type: 'string' },
          detail: { type: 'string' },
          hint: { type: 'string' },
        },
        required: ['code', 'detail'],
      },
    },
  },
  required: ['total', 'entered', 'rejected', 'verdict'],
} as const

export function decisionTools(policy: DecisionPolicy): ToolDefinition[] {
  const auditTool: ToolDefinition = {
    name: 'decision_audit',
    description:
      'Report the quality of this session\'s decision flow: how many steps were entered vs rejected, how many ' +
      'rejections lacked a concrete reason, the worst run of identical rejections, and the worst run of ' +
      'consecutive rejects. verdict="stalled" means the loop is repeating itself and the method must change.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'How many recent violations to include (default 10).' },
      },
    },
    output: {
      schema: AUDIT_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as { limit?: number }
      const report = policy.audit()
      const limit = Math.max(1, a.limit ?? 10)
      return {
        total: report.total,
        entered: report.entered,
        rejected: report.rejected,
        emptyReasons: report.emptyReasons,
        worstRepeat: report.worstRepeat,
        worstStall: report.worstStall,
        verdict: report.verdict,
        violations: report.violations.slice(-limit).map((v) => ({
          code: v.code,
          detail: v.detail,
          hint: v.hint,
        })),
      }
    },
  }

  return [auditTool]
}
