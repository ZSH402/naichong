/**
 * ARTEX 执行体：把 ARTEX 当成一个专项执行者，而不是第二个主控。
 *
 * 定位很重要。ARTEX 自带完整 agent 循环、项目管理和 UI，如果让它自己决策，
 * 就成了「agent 套 agent」——出问题时你不知道该看谁的日志。所以这里只做一件事：
 * 拿一个目标，交给它跑，把 findings 取回来。编排仍然在我们这边。
 *
 * 它比自建工具强的地方在于：真实流量快照 + 证据角色（baseline/proof）+ 覆盖度。
 * 那些东西我们刚起步，它已经跑了很久。
 */

import type { TaskAdapter, TaskContract, TaskResult, AdapterContext } from './contract.ts'

export interface ArtexOptions {
  /** ARTEX 后端地址，例如 http://127.0.0.1:8787 */
  readonly baseUrl: string
  /** 登录密码（首次部署时用 /api/auth/init 设置的）。 */
  readonly password: string
  /** 轮询间隔，默认 5 秒。 */
  readonly pollMs?: number
  /** 任务级超时上限（秒），默认 900。 */
  readonly maxTimeoutSeconds?: number
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
}

interface TaskDto {
  readonly id?: string
  readonly status?: string
  readonly name?: string
  readonly findings?: { readonly critical?: number; readonly high?: number; readonly medium?: number; readonly low?: number; readonly info?: number }
}

const TERMINAL = new Set(['done', 'failed', 'cancelled'])

function findingsTotal(f: TaskDto['findings']): number {
  if (f === undefined) return 0
  return (f.critical ?? 0) + (f.high ?? 0) + (f.medium ?? 0) + (f.low ?? 0) + (f.info ?? 0)
}

export class ArtexClient {
  private readonly options: Required<Omit<ArtexOptions, 'logger'>> & Pick<ArtexOptions, 'logger'>
  private token: string | undefined

  constructor(options: ArtexOptions) {
    this.options = {
      pollMs: 5000,
      maxTimeoutSeconds: 900,
      ...options,
    }
  }

  private async login(): Promise<string> {
    const res = await fetch(`${this.options.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // ARTEX 的 login 要求固定用户名 "ARTEX"（服务端硬编码），不只是密码。
      body: JSON.stringify({ username: 'ARTEX', password: this.options.password }),
    })
    if (!res.ok) throw new Error(`artex login failed: ${res.status} ${await res.text()}`)
    const body = (await res.json()) as { token?: string }
    if (typeof body.token !== 'string') throw new Error('artex login returned no token')
    this.token = body.token
    return body.token
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = this.token ?? (await this.login())
    const doFetch = async (t: string): Promise<Response> =>
      fetch(`${this.options.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${t}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      })

    let res = await doFetch(token)
    // token 过期就重登一次。这里不重试第二次：连续 401 说明密码或权限有问题，
    // 再试只是把同一个错误重复一遍。
    if (res.status === 401) {
      const fresh = await this.login()
      res = await doFetch(fresh)
    }
    if (!res.ok) throw new Error(`artex ${method} ${path} → ${res.status} ${await res.text()}`)
    return (await res.json()) as T
  }

  async health(): Promise<boolean> {
    try {
      const res = await fetch(`${this.options.baseUrl}/api/health`)
      return res.ok
    } catch {
      return false
    }
  }

  async createTask(input: {
    readonly name: string
    readonly goal: string
    readonly description: string
    readonly timeoutSeconds: number
  }): Promise<TaskDto> {
    return this.call<TaskDto>('POST', '/api/tasks', {
      name: input.name,
      goal: input.goal,
      description: input.description,
      timeout_seconds: input.timeoutSeconds,
      // 跳过 planner 直接下发种子意图：我们是主控，规划在我们这边做完了，
      // 让它再规划一遍只会多烧一轮 token 并把目标理解带偏。
      seed_first_intent: true,
      coverage_enabled: true,
    })
  }

  async getTask(id: string): Promise<TaskDto> {
    return this.call<TaskDto>('GET', `/api/tasks/${id}`)
  }
}

/** 把 ARTEX 包成统一执行体。 */
export function createArtexAdapter(client: ArtexClient, options: { readonly logger?: ArtexOptions['logger'] } = {}): TaskAdapter {
  return {
    kind: 'agent',
    describe: 'ARTEX 专项执行者（外部服务，自带流量证据与覆盖度）',
    async execute(contract: TaskContract, ctx: AdapterContext): Promise<TaskResult> {
      const startedAt = Date.now()
      const logger = options.logger
      const timeoutSeconds = Math.min(
        900,
        Math.max(60, Math.round((contract.timeoutMs ?? 300_000) / 1000)),
      )

      let created: TaskDto
      try {
        created = await client.createTask({
          name: contract.id,
          goal: contract.rationale,
          description: contract.rationale,
          timeoutSeconds,
        })
      } catch (error) {
        return {
          contract,
          outcome: 'failed',
          reason: `artex create failed: ${String(error)}`,
          durationMs: Date.now() - startedAt,
          cost: 0,
        }
      }

      const taskId = created.id
      if (taskId === undefined) {
        return { contract, outcome: 'failed', reason: 'artex returned no task id', durationMs: Date.now() - startedAt, cost: 0 }
      }
      logger?.info(`artex: task ${taskId} created for ${contract.direction}`)

      const deadline = startedAt + timeoutSeconds * 1000
      const poll = 5000
      for (;;) {
        if (ctx.signal.aborted) {
          return { contract, outcome: 'failed', reason: 'aborted', durationMs: Date.now() - startedAt, cost: 0 }
        }
        if (Date.now() > deadline) {
          return {
            contract,
            outcome: 'inconclusive',
            reason: `artex task ${taskId} did not finish within ${String(timeoutSeconds)}s`,
            durationMs: Date.now() - startedAt,
            cost: 0,
          }
        }
        await new Promise((r) => setTimeout(r, poll))
        let task: TaskDto
        try {
          task = await client.getTask(taskId)
        } catch (error) {
          logger?.warn(`artex: poll failed for ${taskId}: ${String(error)}`)
          continue
        }
        if (!TERMINAL.has(task.status ?? '')) continue

        const found = findingsTotal(task.findings)
        const f = task.findings
        const detail =
          found === 0
            ? 'no findings recorded'
            : `${String(found)} finding(s): critical=${String(f?.critical ?? 0)} high=${String(f?.high ?? 0)} medium=${String(f?.medium ?? 0)} low=${String(f?.low ?? 0)} info=${String(f?.info ?? 0)}`

        return {
          contract,
          outcome: task.status === 'done' ? 'settled' : 'failed',
          found: found > 0,
          // 证据留在 ARTEX 自己的 data/evidence/ 下（含流量快照与哈希），
          // 不往我们这边复制一份——两份副本迟早会不一致。要复核就用它的 task id 去查。
          detail: `${detail} (artex task ${taskId}; evidence stays on the ARTEX side)`,
          durationMs: Date.now() - startedAt,
          cost: contract.estimatedCost,
          ...(task.status === 'done' ? {} : { reason: `artex task ended as ${String(task.status)}` }),
        }
      }
    },
  }
}
