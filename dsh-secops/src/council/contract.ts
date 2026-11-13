/**
 * 统一任务契约与 Adapter 层。
 *
 * 系统里有三种执行体：确定性代码工具（nuclei/semgrep/rabin2）、专项 agent、
 * 自研 worker。它们形态各异，但对外必须收敛成同一种东西——否则每加一个工具
 * 就要在下游到处加分支，三公的职责也就落不到实处。
 *
 * 契约固定四件事：干什么（direction+target）、谁批准（requestedBy）、
 * 花多少（estimatedCost）、产出归谁（claimId）。其余都是执行细节。
 */

import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import type { Direction } from '../agent-registry.ts'

/** 执行体类型。`mcp` 是外部 MCP server 的工具，和本地 CLI 走不同的执行路径。 */
export type TaskKind = 'code-tool' | 'mcp' | 'agent' | 'worker'

/** 任务发起方，用于审计「谁让它跑的」。 */
export type Requester = 'chancellor' | 'marshal' | 'user'

/** 统一任务契约。 */
export interface TaskContract {
  readonly id: string
  readonly kind: TaskKind
  readonly direction: Direction
  readonly target: string
  readonly claimId?: string
  readonly hypothesisId?: string
  readonly timeoutMs?: number
  /** 预估代价权重（cheap=1 / moderate=3 / expensive=10）。御史大夫据此预扣。 */
  readonly estimatedCost: number
  readonly requestedBy: Requester
  /** 人可读的一句话，说明为什么跑这条。 */
  readonly rationale: string
  /**
   * 太尉为这条任务挑的执行者 id。
   *
   * 同一种 kind 下可能有多个具体执行者（CyberStrikeAI 一个 server 就暴露 81 个工具），
   * 光靠 kind 派活不够——adapter 需要知道该调哪一个。
   */
  readonly agentId?: string
  /**
   * 优先派给哪个 agent。
   *
   * 存在的理由是「同一方向多条任务全落给同一个 agent」：那等于花两次钱
   * 买同一个结论，而号称的多候选一次也没被试过。太尉在拆解时轮转分配，
   * 这条字段把分配结果固定下来，执行层照办。
   */
  readonly preferredAgentId?: string
}

/** 终态。与调度层的四种结果对齐，外加御史大夫的拦截。 */
export type TaskOutcome =
  | 'settled'
  | 'inconclusive'
  | 'failed'
  | 'refused'
  /** 御史大夫没批。 */
  | 'blocked'

/** 证据目录的内容清单，带内容哈希。 */
export interface EvidenceEntry {
  /** 相对证据目录的路径。 */
  readonly path: string
  readonly sha256: string
  readonly size: number
}

export interface EvidenceManifest {
  readonly dir: string
  readonly entries: readonly EvidenceEntry[]
  readonly capturedAt: number
  /** 目录不可读时的原因；有它就不要假装清单是完整的。 */
  readonly error?: string
}

export interface TaskResult {
  readonly contract: TaskContract
  readonly outcome: TaskOutcome
  readonly found?: boolean
  /** 结论强弱：finding 可直接利用 / exposure 暴露面 / clean 干净。 */
  readonly findingClass?: 'finding' | 'exposure' | 'clean'
  readonly detail?: string
  readonly agentId?: string
  readonly evidenceDir?: string
  readonly manifest?: EvidenceManifest
  /** 失败/拦截/未定论的原因。 */
  readonly reason?: string
  readonly durationMs: number
  /** 实际记账的代价。 */
  readonly cost: number
  /** 完整尝试链（有降级时非空）。 */
  readonly attempts?: readonly { readonly agent: string; readonly result: string; readonly fitness?: number }[]
}

/** Adapter 能看到的运行时上下文。 */
export interface AdapterContext {
  readonly signal: AbortSignal
  readonly logger?: { info(msg: string): void; warn(msg: string): void }
}

/** 一种执行体的适配器。 */
export interface TaskAdapter {
  readonly kind: TaskKind
  /** 能力自述，供人才档案与诊断使用。 */
  readonly describe: string
  execute(contract: TaskContract, ctx: AdapterContext): Promise<TaskResult>
}

export class AdapterRegistry {
  private readonly adapters = new Map<TaskKind, TaskAdapter>()

  register(adapter: TaskAdapter): void {
    this.adapters.set(adapter.kind, adapter)
  }

  resolve(kind: TaskKind): TaskAdapter | undefined {
    return this.adapters.get(kind)
  }

  kinds(): TaskKind[] {
    return [...this.adapters.keys()]
  }

  describe(): { kind: TaskKind; describe: string }[] {
    return [...this.adapters.values()].map((a) => ({ kind: a.kind, describe: a.describe }))
  }
}

const HASH_CHUNK = 1024 * 1024
/** 单个证据文件的哈希上限。超过就只记大小不记哈希，免得一个 40G 的 pcap 把派活卡死。 */
const MAX_HASH_BYTES = 256 * 1024 * 1024

function sha256File(file: string, size: number): string {
  if (size > MAX_HASH_BYTES) return `skipped:${size}`
  const hash = createHash('sha256')
  const fd = fs.openSync(file, 'r')
  try {
    const buf = Buffer.allocUnsafe(HASH_CHUNK)
    let read = 0
    // 分块读：证据里可能有很大的抓包或日志，一次性读进内存会直接 OOM。
    for (;;) {
      read = fs.readSync(fd, buf, 0, HASH_CHUNK, null)
      if (read <= 0) break
      hash.update(buf.subarray(0, read))
    }
  } finally {
    fs.closeSync(fd)
  }
  return hash.digest('hex')
}

/**
 * 给证据目录做一份带哈希的清单。
 *
 * 这是「原始证据及哈希」的落点：事后要证明某份日志没被改过，只有内容哈希
 * 是可信的，mtime 谁都能改。清单本身也写进目录，随证据一起走。
 */
export function buildEvidenceManifest(dir: string): EvidenceManifest {
  const capturedAt = Date.now()
  const entries: EvidenceEntry[] = []
  const walk = (current: string, prefix: string): void => {
    for (const name of fs.readdirSync(current).sort()) {
      const full = path.join(current, name)
      const rel = prefix === '' ? name : `${prefix}/${name}`
      const stat = fs.statSync(full)
      if (stat.isDirectory()) {
        walk(full, rel)
        continue
      }
      if (!stat.isFile()) continue
      entries.push({ path: rel, sha256: sha256File(full, stat.size), size: stat.size })
    }
  }
  try {
    walk(dir, '')
  } catch (error) {
    return { dir, entries, capturedAt, error: String(error) }
  }
  const manifest: EvidenceManifest = { dir, entries, capturedAt }
  try {
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
  } catch {
    /* 目录只读就只返回不落盘，不因为写不了清单而让整次派活失败 */
  }
  return manifest
}

/** 清单的摘要，用于把「这批证据是哪一批」压成一个可比较的值。 */
export function manifestDigest(manifest: EvidenceManifest): string {
  const h = createHash('sha256')
  for (const e of manifest.entries) h.update(`${e.path}\u0000${e.sha256}\u0000${e.size}\u0000`)
  return h.digest('hex')
}

let sequence = 0

/** 生成任务 id。带方向与序号，便于在证据目录里一眼看出是哪条。 */
export function nextTaskId(direction: Direction, kind: TaskKind): string {
  sequence += 1
  return `${direction}-${kind}-${sequence}-${Date.now().toString(36)}`
}
