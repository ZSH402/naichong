/**
 * 跨进程任务队列的持久化层。
 *
 * 介质选择：**append-only JSONL 文件**，不是 session log。
 * 理由：队列是跨会话、跨进程的；session log 是会话级且属于 agent 的对话记录，
 * 把调度状态塞进去会让"会话"和"任务"两种生命周期纠缠在一起。
 *
 * 恢复语义：进程崩溃后 `running` 状态的任务不可能还在跑（子进程随父进程组结束），
 * 加载时统一降级为 `interrupted`，由调用方决定重投还是标记失败。
 */

import fs from 'node:fs'
import path from 'node:path'

export type TaskStatus = 'queued' | 'running' | 'done' | 'failed' | 'interrupted' | 'cancelled'

export interface WorkerTask {
  readonly id: string
  readonly kind: string
  readonly argv: readonly string[]
  readonly cwd: string
  readonly timeoutMs: number
  readonly createdAt: number
  readonly status: TaskStatus
  readonly attempts: number
  readonly startedAt?: number
  readonly endedAt?: number
  readonly exitCode?: number | null
  readonly evidenceDir?: string
  readonly note?: string
  /**
   * 这条任务额外的环境变量。
   *
   * 存在理由是「环境依赖不该靠运维记得 export」。`rea` 要 Ghidra 12.1.x，
   * 而系统 apt 装的是 12.2——如果靠 shell 里 export GHIDRA_INSTALL_DIR，
   * 换一种启动方式就悄悄退化成「引擎不可用」，且没有任何地方会报出来。
   * 声明在候选上、随任务落盘，重启和换入口都不丢。
   */
  readonly env?: Record<string, string>
}

interface SubmitRecord {
  readonly t: 'submit'
  readonly task: Omit<WorkerTask, 'status' | 'attempts'>
}
interface StartRecord {
  readonly t: 'start'
  readonly id: string
  readonly at: number
  readonly attempt: number
}
interface FinishRecord {
  readonly t: 'finish'
  readonly id: string
  readonly status: TaskStatus
  readonly at: number
  readonly exitCode?: number | null
  readonly evidenceDir?: string
  readonly note?: string
}
interface RecoverRecord {
  readonly t: 'recover'
  readonly ids: readonly string[]
  readonly at: number
}
type QueueRecord = SubmitRecord | StartRecord | FinishRecord | RecoverRecord

/** 一条 append-only 的任务日志。 */
export class TaskQueueStore {
  private readonly file: string
  private tasks = new Map<string, WorkerTask>()

  constructor(file: string) {
    this.file = file
    fs.mkdirSync(path.dirname(file), { recursive: true })
  }

  /** 从磁盘重放全部记录，返回恢复后的任务表。 */
  load(): Map<string, WorkerTask> {
    this.tasks = new Map()
    if (!fs.existsSync(this.file)) return this.tasks
    const text = fs.readFileSync(this.file, 'utf8')
    for (const line of text.split('\n')) {
      if (line.trim().length === 0) continue
      let rec: QueueRecord
      try {
        rec = JSON.parse(line) as QueueRecord
      } catch {
        // 崩溃可能留下半行，跳过即可 —— append-only 的价值就在这里。
        continue
      }
      this.applyRecord(rec)
    }
    return this.tasks
  }

  private applyRecord(rec: QueueRecord): void {
    switch (rec.t) {
      case 'submit': {
        if (this.tasks.has(rec.task.id)) return
        this.tasks.set(rec.task.id, { ...rec.task, status: 'queued', attempts: 0 })
        return
      }
      case 'start': {
        const prev = this.tasks.get(rec.id)
        if (prev === undefined) return
        this.tasks.set(rec.id, { ...prev, status: 'running', attempts: rec.attempt, startedAt: rec.at })
        return
      }
      case 'finish': {
        const prev = this.tasks.get(rec.id)
        if (prev === undefined) return
        this.tasks.set(rec.id, {
          ...prev,
          status: rec.status,
          endedAt: rec.at,
          ...(rec.exitCode === undefined ? {} : { exitCode: rec.exitCode }),
          ...(rec.evidenceDir === undefined ? {} : { evidenceDir: rec.evidenceDir }),
          ...(rec.note === undefined ? {} : { note: rec.note }),
        })
        return
      }
      case 'recover': {
        for (const id of rec.ids) {
          const prev = this.tasks.get(id)
          if (prev === undefined || prev.status !== 'running') continue
          this.tasks.set(id, { ...prev, status: 'interrupted', endedAt: rec.at, note: 'process exited while running' })
        }
        return
      }
    }
  }

  private append(rec: QueueRecord): void {
    fs.appendFileSync(this.file, `${JSON.stringify(rec)}\n`, 'utf8')
    this.applyRecord(rec)
  }

  /** 提交一个任务。同 id 重复提交是幂等的。 */
  submit(task: Omit<WorkerTask, 'status' | 'attempts'>): WorkerTask {
    const existing = this.tasks.get(task.id)
    if (existing !== undefined) return existing
    this.append({ t: 'submit', task })
    return this.tasks.get(task.id)!
  }

  markRunning(id: string, attempt: number): void {
    this.append({ t: 'start', id, at: Date.now(), attempt })
  }

  markFinished(
    id: string,
    status: TaskStatus,
    extra: { exitCode?: number | null; evidenceDir?: string; note?: string } = {},
  ): void {
    this.append({ t: 'finish', id, status, at: Date.now(), ...extra })
  }

  /** 把上一进程遗留的 running 任务降级为 interrupted。 */
  recoverInterrupted(): string[] {
    const stale = [...this.tasks.values()].filter((t) => t.status === 'running').map((t) => t.id)
    if (stale.length > 0) this.append({ t: 'recover', ids: stale, at: Date.now() })
    return stale
  }

  get(id: string): WorkerTask | undefined {
    return this.tasks.get(id)
  }

  list(): WorkerTask[] {
    return [...this.tasks.values()].sort((a, b) => a.createdAt - b.createdAt)
  }

  get size(): number {
    return this.tasks.size
  }
}
