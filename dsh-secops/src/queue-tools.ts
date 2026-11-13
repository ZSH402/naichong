/**
 * 跨进程调度的模型侧工具：提交任务、查询队列。
 *
 * 工具的 `output.schema` 必须是 lossless JSON，`render` 产模型可见文本。
 * 这里刻意让 `worker_submit` 只返回任务 id 与最终状态 —— 输出正文留在证据目录，
 * 由模型用 fs 工具按需读取，避免把大块 stdout 灌进上下文。
 */

import fs from 'node:fs'
import path from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { QueueRunner } from './queue-runner.ts'
import { digestArtifact, digestArtifactStrict } from './replay.ts'

const STATUS_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    kind: { type: 'string' },
    status: { type: 'string' },
    attempts: { type: 'number' },
    exitCode: { type: 'number' },
    evidenceDir: { type: 'string' },
    note: { type: 'string' },
    archived: { type: 'boolean', description: 'Whether the artifact became claim evidence.' },
    claimId: { type: 'string' },
    rejectReason: { type: 'string', description: 'Why the artifact was rejected as evidence.' },
  },
  required: ['id', 'status'],
} as const

export interface QueueToolOptions {
  /**
   * 提交时声明 claim_id 后，任务以 done 结束会把产物自动附加为该 claim 的证据。
   * pathKey 取 `task:<kind>` —— 同一类工具的重复执行不算独立路径，
   * 这是刻意的：独立复现要求方法本身不同，不是同一命令跑两遍。
   */
  readonly link?: (taskId: string, link: { claimId: string; shape?: string }) => void
  /** 可查询的 claim 列表，供 worker_submit 校验 claim_id 存在。 */
  readonly claimExists?: (claimId: string) => boolean
  /** 任务证据归档结果，供 worker_status 回传给模型。 */
  readonly outcomeOf?: (taskId: string) =>
    | { archived: true; claimId: string }
    | { archived: false; claimId: string; reason: string }
    | undefined
}

export function queueTools(runner: QueueRunner, options: QueueToolOptions = {}): ToolDefinition[] {
  const submit: ToolDefinition = {
    name: 'worker_submit',
    description:
      'Submit a command to the persistent cross-process queue. Returns immediately with a task id; ' +
      'the command runs in its own process group with a timeout, and stdout/stderr land in the evidence directory. ' +
      'Use worker_status to poll. Identical (kind, argv, cwd) submissions are idempotent.',
    parameters: {
      type: 'object',
      properties: {
        kind: { type: 'string', description: 'Task category, e.g. "http-diff" or "nuclei".' },
        argv: {
          type: 'array',
          items: { type: 'string' },
          description: 'Executable and arguments. Never shell-interpreted; use ["sh","-c",...] if you need a shell.',
        },
        cwd: { type: 'string', description: 'Working directory. Defaults to the harness cwd.' },
        timeout_ms: { type: 'number', description: 'Per-task timeout in milliseconds.' },
        claim_id: {
          type: 'string',
          description:
            'Optional claim to attach the task artifacts to. Relevance is judged by argv and by the produced output — ' +
            'a self-written narration is not evidence. Repeating the same tool does not count as an independent path.',
        },

      },
      required: ['kind', 'argv'],
    },
    output: {
      schema: STATUS_SCHEMA as unknown as never,
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    execute: async (args: unknown) => {
      const input = args as {
        kind: string
        argv: string[]
        cwd?: string
        timeout_ms?: number
        claim_id?: string
      }
      if (input.claim_id !== undefined && options.claimExists !== undefined && !options.claimExists(input.claim_id)) {
        return { id: '', kind: input.kind, status: 'rejected', attempts: 0, note: `unknown claim: ${input.claim_id}` }
      }
      const task = runner.submit({
        kind: input.kind,
        argv: input.argv,
        ...(input.cwd === undefined ? {} : { cwd: input.cwd }),
        ...(input.timeout_ms === undefined ? {} : { timeoutMs: input.timeout_ms }),
      })
      if (input.claim_id !== undefined) options.link?.(task.id, { claimId: input.claim_id })
      return {
        id: task.id,
        kind: task.kind,
        status: task.status,
        attempts: task.attempts,
      }
    },
  }

  const status: ToolDefinition = {
    name: 'worker_status',
    description:
      'Read queue state. With id: that task. Without id: the most recent tasks. ' +
      'stdout/stderr are not inlined — read them from the evidence directory.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Task id. Omit to list recent tasks.' },
        limit: { type: 'number', description: 'When listing, how many to return (default 20).' },
      },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          tasks: { type: 'array', items: STATUS_SCHEMA },
        },
        required: ['tasks'],
      } as unknown as never,
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    execute: async (args: unknown) => {
      const input = (args ?? {}) as { id?: string; limit?: number }
      if (input.id !== undefined) {
        const task = runner.get(input.id)
        return { tasks: task === undefined ? [] : [project(task, options.outcomeOf?.(task.id))] }
      }
      const limit = Math.max(1, input.limit ?? 20)
      const all = runner.list()
      return { tasks: all.slice(-limit).map((t) => project(t, options.outcomeOf?.(t.id))) }
    },
  }

  return [submit, status]
}

function project(
  task: {
    id: string
    kind: string
    status: string
    attempts: number
    exitCode?: number | null
    evidenceDir?: string
    note?: string
  },
  outcome?:
    | { archived: true; claimId: string }
    | { archived: false; claimId: string; reason: string },
): Record<string, unknown> {
  return {
    id: task.id,
    kind: task.kind,
    status: task.status,
    attempts: task.attempts,
    ...(task.exitCode === undefined || task.exitCode === null ? {} : { exitCode: task.exitCode }),
    ...(task.evidenceDir === undefined ? {} : { evidenceDir: task.evidenceDir }),
    ...(task.note === undefined ? {} : { note: task.note }),
    // 归档结果必须回传：模型需要知道证据有没有被采纳、为什么没被采纳。
    ...(outcome === undefined
      ? {}
      : outcome.archived
        ? { archived: true, claimId: outcome.claimId }
        : { archived: false, claimId: outcome.claimId, rejectReason: outcome.reason }),
  }
}

/** 注册队列工具。返回卸载器。 */
export function installQueueTools(ctx: Context, runner: QueueRunner, options: QueueToolOptions = {}): void {
  for (const tool of queueTools(runner, options)) ctx.tools.register(tool)
}

/**
 * 把队列完成事件接到 claim 体系的归档器。
 *
 * 抽成独立函数而不是内联在 apply 里，是为了让测试能验证同一份逻辑，
 * 而不是复制一段"看起来一样"的组装代码。
 */
export interface EvidenceArchiver {
  /** 供 QueueRunner 的 onFinish 使用。 */
  readonly onFinish: (task: {
    id: string
    kind: string
    status: string
    argv?: readonly string[]
    cwd?: string
    exitCode?: number | null
    evidenceDir?: string
  }) => void
  /** 供 queueTools 的 link / claimExists。 */
  readonly options: QueueToolOptions
  /** 尚未结算的 task → claim 关联数（测试与诊断用）。 */
  readonly pendingCount: () => number
  /** 最近一次被相关性校验拒绝的记录（诊断用）。 */
  readonly lastRejection: () => { taskId: string; claimId: string; reason: string } | undefined
  /**
   * 某个任务最终是否归档成了证据。
   * 必须暴露给模型：端到端验证里模型只能靠读源码复算拒绝原因，
   * 因为工具从来没告诉它「你的证据被拒了、为什么」。
   */
  readonly outcomeOf: (taskId: string) =>
    | { readonly archived: true; readonly claimId: string }
    | { readonly archived: false; readonly claimId: string; readonly reason: string }
    | undefined
}

type AttachCapable = {
  attach(
    id: string,
    evidence: {
      ref: string
      pathKey: string
      note?: string
      executed?: string
      artifact?: string
      source?: { kind: 'worker'; taskId: string; argv: string[]; cwd: string }
      baselineDigest?: string
      baselineStrictDigest?: string
    },
  ): { ok: boolean; reason?: string }
  get(id: string): unknown
  /**
   * 记下断言产生的目标形态。可选：不带这个能力的 store 会静默跳过，
   * 信誉退回不分层的旧行为，而不是崩掉。
   */
  setShape?(claimId: string, shape: string | undefined): unknown
}

/** 产物摘要上限：只读开头一段，足够匹配锚点，又不把大文件读进内存。 */
const ARTIFACT_SNIFF_BYTES = 8192

/** 从证据目录读 stdout/stderr 摘要作为 artifact 判据。 */
function sniffArtifact(evidenceDir: string | undefined): string | undefined {
  if (evidenceDir === undefined) return undefined
  const parts: string[] = []
  for (const name of ['stdout.log', 'stderr.log']) {
    try {
      const buf = Buffer.alloc(ARTIFACT_SNIFF_BYTES)
      const fd = fs.openSync(path.join(evidenceDir, name), 'r')
      let read = 0
      try {
        read = fs.readSync(fd, buf, 0, ARTIFACT_SNIFF_BYTES, 0)
      } finally {
        fs.closeSync(fd)
      }
      if (read > 0) parts.push(buf.subarray(0, read).toString('utf8'))
    } catch {
      /* 文件不存在就跳过 */
    }
  }
  return parts.length === 0 ? undefined : parts.join('\n')
}

export function createEvidenceArchiver(claimStore: AttachCapable): EvidenceArchiver {
  const pending = new Map<string, { claimId: string; shape?: string }>()
  const outcomes = new Map<
    string,
    { archived: true; claimId: string } | { archived: false; claimId: string; reason: string }
  >()
  let rejection: { taskId: string; claimId: string; reason: string } | undefined
  return {
    onFinish(task) {
      const link = pending.get(task.id)
      if (link === undefined) return
      pending.delete(task.id)
      // 先记形态再挂证据：形态是这条断言「在什么世界里得出的」这个事实，
      // 和证据成败无关——即使这次执行失败了也该记下来（只是没证据可挂）。
      claimStore.setShape?.(link.claimId, link.shape)
      // 只有成功结束才算证据：失败任务说明命令没跑通，不是对断言的观测。
      if (task.status !== 'done' || task.evidenceDir === undefined) return
      const artifact = sniffArtifact(task.evidenceDir)
      // executed 用实际 argv：这是「证据必须触及断言锚点」的主判据，
      // 模型无法只靠自述把无关命令冒充成证据。
      // source + baselineDigest 让证据可重放：claim_verify 会用同一 argv 重跑并比对骨架。
      const result = claimStore.attach(link.claimId, {
        ref: `task:${task.id}`,
        pathKey: `task:${task.kind}`,
        note: `queue task ${task.kind} exit=${String(task.exitCode)} evidence=${task.evidenceDir}`,
        ...(task.argv === undefined ? {} : { executed: task.argv.join(' ') }),
        ...(artifact === undefined ? {} : { artifact }),
        ...(task.argv === undefined
          ? {}
          : {
              source: {
                kind: 'worker' as const,
                taskId: task.id,
                argv: [...task.argv],
                cwd: task.cwd ?? process.cwd(),
              },
              baselineDigest: digestArtifact(artifact ?? '', ''),
              baselineStrictDigest: digestArtifactStrict(artifact ?? '', ''),
            }),
      })
      if (result.ok) {
        outcomes.set(task.id, { archived: true, claimId: link.claimId })
      } else {
        const reason = result.reason ?? 'rejected'
        rejection = { taskId: task.id, claimId: link.claimId, reason }
        outcomes.set(task.id, { archived: false, claimId: link.claimId, reason })
      }
    },
    options: {
      link: (taskId, link) => pending.set(taskId, { claimId: link.claimId, ...(link.shape === undefined ? {} : { shape: link.shape }) }),
      claimExists: (id) => claimStore.get(id) !== undefined,
    },
    pendingCount: () => pending.size,
    lastRejection: () => rejection,
    outcomeOf: (taskId) => outcomes.get(taskId),
  }
}
