/**
 * 决策记录：知识点级的决策留痕，随 session log 持久化。
 *
 * 用 DSH 官方插件扩展点，不碰核心：
 *   - 写入：`appendPluginRecord(session, 'plugin:secops-decision', record)`
 *   - 读取：`pluginRecordOf(event)` 在 projection 里还原
 *
 * 为什么不用自建存储：session log 本身是 append-only + 可 replay + 可导出的，
 * projection 会在会话恢复后自动重建。自建一套会和 DSH 的证据引用链路断开。
 */

import { z } from 'zod'
import { appendPluginRecord, pluginRecordOf, type Session } from '@deepseek-ai/dsh-session'
import type { SessionEvent } from '@deepseek-ai/dsh-session'

const rejectedItemSchema = z.object({
  what: z.string(),
  why: z.string(),
})

/**
 * 一条决策记录。字段刻意区分「事实」与「叙事」：
 * `rationale` 不存在，只有 `evidenceRefs` —— 没有证据引用的决策在复盘时应视为无效。
 */
export const decisionSchema = z.object({
  decisionId: z.string(),
  turn: z.number(),
  step: z.number(),
  agentId: z.string(),
  /** enter = 进入该步；reject = 拒绝。 */
  kind: z.enum(['enter', 'reject']),
  /** reject 的具体理由（enter 时通常缺省）。 */
  reason: z.string().optional(),
  /** 候选方向/动作。空数组表示未显式列出。 */
  candidates: z.array(z.string()),
  /** 实际选择。 */
  chosen: z.string().optional(),
  /** 依据。必须指向证据，不是自然语言自述。 */
  evidenceRefs: z.array(z.string()),
  /** 被放弃的选项及各自理由。 */
  rejected: z.array(rejectedItemSchema),
  /** 如果这个决策错了，什么观测会暴露它。 */
  falsifier: z.string().optional(),
  /** 认为「证据够了」的判据（决定停止时填）。 */
  saturation: z.string().optional(),
})

export type DecisionRecordData = z.infer<typeof decisionSchema>

export const decisionStateSchema = z.object({
  decisions: z.array(decisionSchema),
  rejectedCount: z.number(),
  enteredCount: z.number(),
  lastTurn: z.number(),
})

export type DecisionProjectionState = z.infer<typeof decisionStateSchema>

declare module '@deepseek-ai/dsh-session' {
  interface PluginRecordMap {
    'plugin:secops-decision': DecisionRecordData
  }
}

/** 决策记录的 projection key。 */
export const DECISION_PROJECTION_KEY = 'secopsDecisions'

/** 记录类型，必须在 `plugin:` 命名空间内。 */
export const RECORD_TYPE = 'plugin:secops-decision' as const

const EMPTY_STATE: DecisionProjectionState = {
  decisions: [],
  rejectedCount: 0,
  enteredCount: 0,
  lastTurn: 0,
}

/**
 * 写入一条决策记录。
 *
 * `appendPluginRecord` 是 dsh-session 的官方插件扩展点：type 必须落在
 * `plugin:` 命名空间，payload 必须是可序列化 JSON。
 */
export function recordDecision(session: Session, record: DecisionRecordData): number {
  return appendPluginRecord(session, RECORD_TYPE, record)
}

/**
 * 注册决策记录的 host-only projection。
 *
 * host-only（不带 wire）意味着它不进客户端快照，但照样 checkpoint，
 * 因此会话恢复后状态可重建。
 */
export interface ProjectionRegistryLike {
  register(definition: unknown): Promise<unknown>
  stateOf?(session: unknown, key: string): unknown
}

export async function registerDecisionProjection(registry: ProjectionRegistryLike): Promise<void> {
  await registry.register({
    key: DECISION_PROJECTION_KEY,
    stateVersion: 1,
    stateSchema: decisionStateSchema,
    init: () => EMPTY_STATE,
    apply(state: DecisionProjectionState, event: SessionEvent): DecisionProjectionState {
      // plugin: 命名空间的事件不进 SessionEventMap，用官方读取器还原，
      // 避免对 event.type 做字符串比较（类型上不重叠）。
      const rec = pluginRecordOf(event)
      if (rec === undefined || rec.type !== RECORD_TYPE) return state
      const record = rec.data as DecisionRecordData
      return {
        decisions: [...state.decisions, record],
        rejectedCount: state.rejectedCount + (record.kind === 'reject' ? 1 : 0),
        enteredCount: state.enteredCount + (record.kind === 'enter' ? 1 : 0),
        lastTurn: record.turn,
      }
    },
  })
}

/** 从 projection 读取某 session 的全部决策。 */
export function readDecisions(
  registry: ProjectionRegistryLike,
  session: unknown,
): DecisionProjectionState | undefined {
  if (registry.stateOf === undefined) return undefined
  return registry.stateOf(session, DECISION_PROJECTION_KEY) as DecisionProjectionState | undefined
}
