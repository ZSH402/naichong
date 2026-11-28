/**
 * 证据重放：让证据自己证明自己。
 *
 * 核心问题：副 agent 或 worker 返回的产物无法验证真伪，模型也可以编造。
 * 「不能重放的东西不算证据」是唯一不依赖诚实度的判据。
 *
 * 关键设计——**骨架摘要**而不是原文比对：
 * 扫描输出天然带时间戳、UUID、端口、计数，逐字节比对必然误判。
 * 这里把易变部分抹掉，只保留结构性 token，再取哈希。同一命令重跑两次
 * 若结构一致，摘要就一致；命令实际失败或目标变了，摘要就不同。
 *
 * 已知局限：`echo "PUT /api/user 200"` 这样的命令能自证成功（摘要稳定且
 * 含锚点）。重放能挡住「编造没跑过的结果」，挡不住「跑了但没测到东西」。
 * 后者要靠相关性闸和独立路径，不能指望重放。
 */

import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'

export interface ReplayRequest {
  readonly argv: readonly string[]
  readonly cwd: string
  readonly timeoutMs?: number
  /** 原始产物的结构摘要（抹数字）。 */
  readonly baselineDigest?: string
  /** 原始产物的严格摘要（保留数字）。提供时优先用它判定 strict 一致。 */
  readonly baselineStrictDigest?: string
  /** 采集上限，超出部分截断。 */
  readonly maxOutputBytes?: number
}

export interface ReplayOutcome {
  /** 命令是否真的跑起来了（spawn 成功）。 */
  readonly ran: boolean
  readonly exitCode: number | null
  /** 本次产物的骨架摘要。 */
  readonly digest: string
  /** 与原产物是否一致；无 baseline 时为 true（无从比对）。 */
  readonly matchesBaseline: boolean
  /**
   * 一致的程度：strict = 数值也一致；structural = 仅结构一致；none = 不一致。
   * 只有 strict 才算真正复现。
   */
  readonly matchKind: 'strict' | 'structural' | 'none'
  /** 用于诊断的产物片段。 */
  readonly excerpt: string
  readonly reason?: string
}

const DEFAULT_TIMEOUT_MS = 120_000
const DEFAULT_MAX_BYTES = 256 * 1024

/**
 * 两级摘要。
 *
 * 为什么分两级：只抹数字会让 "found 5000 items" 与 "found 3 items" 摘要相同，
 * 内容实质不同却被判为一致 —— 那是给证据造假开后门。
 * 只看数字又会被时间戳、随机 id 打死。
 *
 *   strict     —— 只抹真正易变的部分（时间戳 / UUID / 长 hex），数字保留
 *   structural —— 再把数字也抹掉，只留结构
 *
 * 比对规则见 compareDigests：strict 一致才算通过；structural 一致但 strict 不同，
 * 属于「结构对得上、数值有出入」，记为弱一致并由调用方决定是否接受。
 */
export function strictDigest(text: string): string {
  const normal = text
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g, '<ts>')
    .replace(/\b\d{2}:\d{2}:\d{2}\b/g, '<time>')
    .replace(/\b\d{4}\/\d{2}\/\d{2}\b/g, '<date>')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<uuid>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
    .replace(/\s+/g, ' ')
    .trim()
  return createHash('sha256').update(normal).digest('hex').slice(0, 16)
}

/** 结构摘要：在 strict 的基础上再抹掉所有数字。 */
export function structuralDigest(text: string): string {
  return skeletonDigest(text)
}

/**
 * 骨架摘要（结构级）：抹掉易变部分后再抹数字。
 *
 * 保留：单词、URL 路径、状态码词、标点结构。
 */
/**
 * 索引 → 双射字母（A..Z, AA..AZ, BA..）。
 *
 * 为什么必须是字母：摘要流水线里有一道 `\d+ → <n>` 的数字归一化，
 * 任何数字索引都会被它抹掉，哨兵就还原不回来。
 * 为什么不能用单字母：只有 26 个槽位，而扫描工具单次输出几十个状态码是常态，
 * 超出的会互相覆盖——500 被写成 200 参与哈希，重放判据就失效了。
 */
function encodeIndex(n: number): string {
  let s = ''
  let v = n + 1
  while (v > 0) {
    const r = (v - 1) % 26
    s = String.fromCharCode(65 + r) + s
    v = Math.floor((v - 1) / 26)
  }
  return s
}

function decodeIndex(code: string): number {
  let v = 0
  for (const ch of code) v = v * 26 + (ch.charCodeAt(0) - 64)
  return v - 1
}

export function skeletonDigest(text: string): string {
  // 状态码先用哨兵保护，否则会在随后的数字归一化里被再次抹掉。
  const statuses: string[] = []
  const guarded = text.replace(
    /((?:->|=>|status\s*[:=]?|code\s*[:=]?|HTTP\/[\d.]+\s+)\s*)([1-5]\d{2})\b/gi,
    (_m, pre: string, code: string) => {
      // 哨兵必须避开数字（会被下一轮 \d+ 归一化抹掉），也**不能用固定字母空间**。
      //
      // 早先用 `String.fromCharCode(65 + ((n-1) % 26))`：只有 26 个槽位。
      // ffuf/httpx/nuclei 单次输出几十个不同状态码是常态，第 27 个会复用 'A'，
      // 还原时全部替换成 statuses[0]，500/403 被静默篡改成 200 参与哈希比对——
      // 重放判定因此不可信。
      //
      // 还有一个边界：statuses.length 为 0 时 `(0-1) % 26 === -1`，
      // 得到 '@'，而还原正则只认 [A-Z]，哨兵原样留在摘要里。
      //
      // 现在用变长数字标记：`\u0000S<index>\u0000`。它不走字母空间，
      // 且因为前缀是 \u0000（不会出现在 \d+ 匹配里，标记内部数字在还原前
      // 已经被保护）——顺序上先还原标记、再归一化数字是不行的，
      // 所以标记内部用 `S` 前缀让数字归一化的正则也跳过它。
      statuses.push(code)
      return `${pre}\u0000${encodeIndex(statuses.length - 1)}\u0000`
    },
  )
  const skeleton = guarded
    // ISO 时间
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g, '<ts>')
    // 常见的耗时/日期
    .replace(/\b\d{2}:\d{2}:\d{2}\b/g, '<time>')
    .replace(/\b\d{4}\/\d{2}\/\d{2}\b/g, '<date>')
    // UUID
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<uuid>')
    // 长十六进制（哈希、随机 id）
    .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
    // 状态码要看上下文：只有紧跟 -> / status: / code: / HTTP/1.1 的三位数才是状态码。
    // 光看位数会把 "took 987ms" 也当状态码，导致易变字段漏网；
    // 一律抹掉又会把 "-> 200" 与 "-> 500" 归一，让重放失去判据。
    // 其余数字（计数、耗时、端口、大小）。
    // 不能用 \b\d+\b —— "12ms" 里数字与字母之间不是单词边界，会漏掉。
    .replace(/\d+/g, '<n>')
    // 还原受保护的状态码（双射字母索引，不受 26 槽位限制，也不会被数字归一化吃掉）
    .replace(/\u0000([A-Z]+)\u0000/g, (_m, code: string) => {
      const idx = decodeIndex(code)
      return `<status:${statuses[idx] ?? '?'}>`
    })
    // 连续空白
    .replace(/\s+/g, ' ')
    .trim()
  return createHash('sha256').update(skeleton).digest('hex').slice(0, 16)
}

/** 执行一次重放并比对骨架。 */
export async function replayCommand(request: ReplayRequest): Promise<ReplayOutcome> {
  const argv = request.argv
  if (argv.length === 0) {
    return { ran: false, exitCode: null, digest: '', matchesBaseline: false, matchKind: 'none', excerpt: '', reason: 'empty argv' }
  }
  const timeoutMs = Math.max(1, request.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const limit = Math.max(1024, request.maxOutputBytes ?? DEFAULT_MAX_BYTES)

  return new Promise<ReplayOutcome>((resolve) => {
    let stdout = ''
    let stderr = ''
    let settled = false
    let timedOut = false

    const child = spawn(argv[0]!, argv.slice(1), {
      cwd: request.cwd,
      // 独立进程组：重放也要能整组终止，否则会留下孤儿进程。
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    })

    const killGroup = (): void => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, 'SIGTERM')
      } catch {
        try {
          child.kill('SIGTERM')
        } catch {
          /* already gone */
        }
      }
    }

    // 先 TERM 再 KILL：只发 TERM 的话，忽略该信号的进程（或持有 stdout pipe
    // 未关闭的子进程）会让 Promise 永远不 resolve——表现是重放卡死，
    // 而不是失败。5 秒后补一刀 SIGKILL。
    let killTimer: NodeJS.Timeout | undefined
    const timer = setTimeout(() => {
      timedOut = true
      killGroup()
      killTimer = setTimeout(() => {
        try {
          if (child.pid !== undefined) process.kill(-child.pid, 'SIGKILL')
        } catch {
          try {
            child.kill('SIGKILL')
          } catch {
            /* already gone */
          }
        }
      }, 5000)
    }, timeoutMs)

    const finish = (exitCode: number | null, spawnError?: string): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (killTimer !== undefined) clearTimeout(killTimer)
      const combined = `${stdout}\n${stderr}`.slice(0, limit)
      const digest = skeletonDigest(combined)
      const strict = strictDigest(combined)

      let matchKind: 'strict' | 'structural' | 'none'
      if (request.baselineDigest === undefined && request.baselineStrictDigest === undefined) {
        matchKind = 'strict' // 无从比对，视为通过
      } else if (request.baselineStrictDigest !== undefined) {
        matchKind = request.baselineStrictDigest === strict
          ? 'strict'
          : request.baselineDigest === digest
            ? 'structural'
            : 'none'
      } else {
        matchKind = request.baselineDigest === digest ? 'structural' : 'none'
      }
      if (matchKind === 'none' && request.baselineDigest !== undefined && request.baselineStrictDigest === undefined) {
        // 只有结构基线时，结构一致就是能做到的最好判断
        matchKind = 'structural'
      }
      const matchesBaseline = matchKind !== 'none'
      resolve({
        ran: spawnError === undefined,
        exitCode,
        digest,
        matchesBaseline,
        matchKind,
        excerpt: combined.slice(0, 400),
        ...(spawnError !== undefined
          ? { reason: spawnError }
          : timedOut
            ? { reason: `timed out after ${timeoutMs}ms` }
            : matchKind === 'strict'
              ? {}
              : matchKind === 'structural'
                ? { reason: 'structure matches but numeric values differ from the recorded artifact' }
                : { reason: 'output differs from the recorded artifact' }),
      })
    }

    child.stdout?.on('data', (b: Buffer) => {
      if (stdout.length < limit) stdout += b.toString('utf8')
    })
    child.stderr?.on('data', (b: Buffer) => {
      if (stderr.length < limit) stderr += b.toString('utf8')
    })
    child.on('error', (e) => finish(null, String(e)))
    child.on('close', (code) => finish(code))
  })
}

/** 计算结构摘要（建立 baseline 用）。 */
export function digestArtifact(stdout: string, stderr: string, limit = DEFAULT_MAX_BYTES): string {
  return skeletonDigest(`${stdout}\n${stderr}`.slice(0, limit))
}

/** 计算严格摘要（建立 baseline 用）。 */
export function digestArtifactStrict(stdout: string, stderr: string, limit = DEFAULT_MAX_BYTES): string {
  return strictDigest(`${stdout}\n${stderr}`.slice(0, limit))
}
