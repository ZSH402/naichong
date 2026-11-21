/**
 * 交互式会话管理：让 agent 能对**长驻程序**发命令、读响应，而不是每次都起一个新进程。
 *
 * ## 为什么需要
 *
 * EnIGMA（arXiv 2409.16165, ICML 2025）在 350 道 CTF 题上验证：**交互式工具是最大
 * 的单点改进**。原因是 CTF 必需的 gdb / nc / pwntools 都是 REPL —— 它们的价值在于
 * 「进去、看状态、再决定下一步」，而"一次性命令 + 拿输出"的接口逼 agent 预先枚举
 * 所有交互，这在真实调试里不可能做到。
 *
 * ## 与 EnIGMA 的差异（本实现的取舍）
 *
 * 1. **不硬编码工具命令**。EnIGMA 给了 `debug_start/step/continue/exec` 六件套，
 *    但奶虫的 registry 有 27 个候选、以后还会加。这里做**通用会话 + 协议适配器**：
 *    协议决定"怎么判断响应结束"，工具本身只是一条 argv。
 *
 * 2. **用 token 而不是等 prompt**。EnIGMA 读 gdb 的 `(gdb) ` 提示符判断结束。
 *    提示符可能出现在输出内容里（比如被调试程序自己打印了 `(gdb)` 串），
 *    一旦撞上就会提前返回、截断真实结果。gdb MI 支持 `<token><command>`，
 *    响应行带同一 token 前缀，**这是协议级的多路复用，不会撞车**。
 *
 * 3. **允许并发多个会话**。EnIGMA 限制"同时只有 1 个交互会话"以降低复杂度。
 *    但真实场景确实需要一边调试一边连远程服务（EnIGMA 自己的 Figure 3 就是
 *    在 gdb 和服务器之间来回切，只是靠串行模拟）。这里允许最多 `maxSessions` 个，
 *    默认 4。
 *
 * 4. **不做完整 MI 解析**。pygdbmi 把 MI 输出解析成结构化 dict，代价是要维护一个
 *    覆盖全部 record 类型的解析器。这里只做 **token 定界 + 原样返回**：agent 读得懂
 *    MI 文本，而解析器是最容易长出 bug 的地方。少一层就少一类静默错误。
 *
 * ## 生命周期
 *
 * `spawn(detached: true)` → 整个进程组可一次性回收。会话关闭、超时、插件卸载
 * 三条路径都会打 `kill(-pid)`，避免 gdb 被调程序这类子进程变孤儿。
 */

import { spawn, type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

/** 会话协议：决定「一条命令的响应什么时候算结束」。 */
export type SessionProtocol =
  /** gdb machine interface：`<token><cmd>`，等 token 前缀的 result record。 */
  | 'gdb-mi'
  /** 通用 REPL / 网络连接：发一行，等静默 `idleMs` 后返回累积输出。 */
  | 'quiet'
  /**
   * pwntools 桥接（`tools/pwn_session.py`）：发一行 JSON，读一行 JSON 响应。
   *
   * 为什么单独一个协议而不是复用 quiet：pwntools 的核心价值是**区分超时与 EOF**、
   * 以及 `recv(numb=N)` 的精确字节数，而 quiet 只能靠"静默多久"猜。
   * 在 pwn 题里把 EOF 当超时会让 agent 在程序已退出后继续等，代价是整轮超时。
   */
  | 'pwn'

export interface SessionSpec {
  readonly protocol: SessionProtocol
  /** 完整 argv，第一项是可执行文件。 */
  readonly argv: readonly string[]
  readonly cwd: string
  readonly env?: Readonly<Record<string, string>>
  /** 人类可读标签，进日志。 */
  readonly label?: string
}

export interface SessionInfo {
  readonly id: string
  readonly protocol: SessionProtocol
  readonly label: string
  readonly pid: number | undefined
  readonly alive: boolean
  readonly bytesOut: number
  readonly startedAt: number
}

export interface ExecOptions {
  /** 等首字节的上限。默认 10s。 */
  readonly waitMs?: number
  /** 收到数据后，静默多久算结束。默认 400ms（gdb 用 120ms，它有 token 定界）。 */
  readonly idleMs?: number
  /** 返回的最大字符数，超出则截断并标注。默认 12_000。 */
  readonly maxChars?: number
}

export interface ExecResult {
  readonly output: string
  readonly truncated: boolean
  readonly timedOut: boolean
  readonly exitCode: number | null
  readonly elapsedMs: number
}

const DEFAULT_MAX_SESSIONS = 4
const DEFAULT_WAIT_MS = 10_000
const RING_LIMIT = 256 * 1024
const GDB_IDLE_MS = 120

interface Pending {
  readonly token: string
  readonly resolve: (text: string) => void
  readonly timer: NodeJS.Timeout
  readonly idleTimer: NodeJS.Timeout
  buffer: string
  sawBytes: boolean
}

class Session {
  readonly id = randomUUID()
  readonly startedAt = Date.now()
  private proc: ChildProcess | undefined
  private ring = ''
  private bytesOut = 0
  private alive = true
  private exitCode: number | null = null
  private counter = 0
  private pending: Pending | undefined
  private lastByteAt = 0
  private readonly logStream: fs.WriteStream | undefined

  constructor(
    readonly spec: SessionSpec,
    logDir: string | undefined,
  ) {
    if (logDir !== undefined) {
      fs.mkdirSync(logDir, { recursive: true })
      this.logStream = fs.createWriteStream(path.join(logDir, `session-${this.id}.log`), { flags: 'a' })
    }
  }

  start(): void {
    const [cmd, ...args] = this.spec.argv
    if (cmd === undefined) throw new Error('session: argv 为空')
    // detached 让整个进程组可回收：gdb 会 fork 被调试程序，只杀 gdb 会留孤儿。
    this.proc = spawn(cmd, args, {
      cwd: this.spec.cwd,
      env: { ...process.env, ...this.spec.env },
      detached: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.proc.stdout?.setEncoding('utf8')
    this.proc.stderr?.setEncoding('utf8')
    const onData = (chunk: string): void => {
      this.bytesOut += chunk.length
      this.ring = (this.ring + chunk).slice(-RING_LIMIT)
      this.logStream?.write(chunk)
      this.pump(chunk)
    }
    this.proc.stdout?.on('data', onData)
    this.proc.stderr?.on('data', onData)
    this.proc.on('exit', (code) => {
      this.alive = false
      this.exitCode = code
      // 进程自己退了，把还在等的调用唤醒，别让它白等到超时
      const p = this.pending
      if (p !== undefined) {
        clearTimeout(p.timer)
        this.pending = undefined
        p.resolve(p.buffer)
      }
    })
    this.proc.on('error', () => {
      this.alive = false
    })
  }

  /** 把新数据喂给等待中的请求，判断是否满足结束条件。 */
  private pump(chunk: string): void {
    this.lastByteAt = Date.now()
    const p = this.pending
    if (p === undefined) return
    p.buffer += chunk
    p.sawBytes = true
    // gdb-mi 有 token 定界，pwn 有单行 JSON 定界，两者都能立刻收；quiet 只能等静默
    if (this.spec.protocol === 'gdb-mi' && tokenSettled(p.buffer, p.token)) {
      this.settle(p.buffer)
    } else if (this.spec.protocol === 'pwn' && pwnSettled(p.buffer)) {
      this.settle(p.buffer)
    }
  }

  /** 结束当前等待并清理两个计时器。所有路径都走这里，避免漏清。 */
  private settle(text: string): void {
    const p = this.pending
    if (p === undefined) return
    clearTimeout(p.timer)
    clearInterval(p.idleTimer)
    this.pending = undefined
    p.resolve(text)
  }

  write(text: string): void {
    const stdin = this.proc?.stdin
    if (!this.alive || stdin === null || stdin === undefined) throw new Error('session: 已结束，无法写入')
    stdin.write(text)
  }

  async exec(command: string, opts: ExecOptions = {}): Promise<ExecResult> {
    const started = Date.now()
    const waitMs = opts.waitMs ?? DEFAULT_WAIT_MS
    // pwn 协议有单行 JSON 定界，绝不能用静默判定去截断它——
    // ready 行或缓慢的 recv 都会让 idle 提前把响应截掉。给一个实际不会触发的值。
    const idleMs =
      opts.idleMs ??
      (this.spec.protocol === 'gdb-mi' ? GDB_IDLE_MS : this.spec.protocol === 'pwn' ? 1_000_000 : 400)
    const maxChars = opts.maxChars ?? 12_000

    this.counter += 1
    const token = String(this.counter)
    // gdb-mi 用 token 定界；pwn 把简化语法翻成 JSONL；quiet 原样发一行
    const line =
      this.spec.protocol === 'gdb-mi'
        ? `${token}${command}\n`
        : this.spec.protocol === 'pwn'
          ? `${encodePwnRequest(command)}\n`
          : `${command}\n`

    const text = await new Promise<string>((resolve) => {
      let done = false
      const finish = (value: string): void => {
        if (done) return
        done = true
        resolve(value)
      }
      // 首字节超时：waitMs 内一个字节都没来，认栽返回空
      const timer = setTimeout(() => this.settle(''), waitMs)
      // 静默判定：quiet 协议唯一能用的结束条件；gdb-mi 用它兜底（比如命令没回 result）
      const idleTimer = setInterval(() => {
        const p = this.pending
        if (p === undefined) return
        if (p.sawBytes && Date.now() - this.lastByteAt >= idleMs) this.settle(p.buffer)
      }, 40)
      this.lastByteAt = Date.now()
      this.pending = { token, buffer: '', sawBytes: false, timer, idleTimer, resolve: finish }
      try {
        this.write(line)
      } catch {
        this.settle('')
      }
    })

    this.pending = undefined
    const transformed = this.spec.protocol === 'pwn' ? decodePwnResponse(text) : text
    const elapsedMs = Date.now() - started
    const truncated = transformed.length > maxChars
    const output = truncated
      ? `${transformed.slice(0, maxChars)}\n…（已截断，原始 ${transformed.length} 字符，完整内容见会话日志）`
      : transformed
    return {
      output,
      truncated,
      timedOut: transformed === '' && this.alive,
      exitCode: this.exitCode,
      elapsedMs,
    }
  }

  /**
   * 等启动握手。
   *
   * pwn 桥接启动后会立刻吐一行 `{"ready":true}`。这行的数据事件可能在第一次
   * `exec` 之后才触发（spawn 是异步的），于是它会被当成第一条命令的响应——
   * 实测就是这样：`sendline:hello` 拿回来的是 ready 行。
   * 显式消费掉它，别让它污染后续响应。
   */
  async waitReady(timeoutMs = 5000): Promise<boolean> {
    if (this.spec.protocol !== 'pwn') return true
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      if (this.ring.includes('"ready"')) return true
      if (!this.alive) return false
      await new Promise((r) => setTimeout(r, 30))
    }
    return false
  }

  info(): SessionInfo {
    return {
      id: this.id,
      protocol: this.spec.protocol,
      label: this.spec.label ?? this.spec.argv.join(' '),
      pid: this.proc?.pid,
      alive: this.alive,
      bytesOut: this.bytesOut,
      startedAt: this.startedAt,
    }
  }

  /** 最近 N 字符的原始流（用于"刚才发生了什么"的回看）。 */
  tail(n = 4000): string {
    return this.ring.slice(-n)
  }

  async close(): Promise<void> {
    const proc = this.proc
    if (proc === undefined) return
    const pid = proc.pid
    this.alive = false
    if (pid !== undefined) {
      // 打整个进程组：gdb fork 出来的被调试程序一起收
      try {
        process.kill(-pid, 'SIGTERM')
      } catch {
        try {
          process.kill(pid, 'SIGTERM')
        } catch {
          /* 已经没了 */
        }
      }
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => {
          try {
            process.kill(-pid, 'SIGKILL')
          } catch {
            /* ignore */
          }
          resolve()
        }, 1500)
        proc.once('exit', () => {
          clearTimeout(t)
          resolve()
        })
      })
    }
    this.logStream?.end()
  }
}

/**
 * 判断 gdb-mi 的响应是否已经完整。
 *
 * 规则：**必须看到 `<token>^` 开头的 result record**（`^done` / `^error` / `^running` / `^connected`）。
 *
 * ⚠️ 但 `^running` 不代表命令结束——`-exec-run` 后 gdb 先回 `^running`，
 * 真正的停止要等异步的 `*stopped`。所以看到 `^running` 还要继续等到
 * `*stopped` 或 `*running` 之后的下一个 result。这条是实测踩出来的：
 * 只认 `^done` 会让 `-exec-run` 一直等到超时。
 */
function tokenSettled(buffer: string, token: string): boolean {
  const lines = buffer.split('\n')
  let sawResult = false
  let runningAwaitingStop = false
  for (const raw of lines) {
    const line = raw.trimStart()
    if (!line.startsWith(token)) continue
    const rest = line.slice(token.length)
    if (rest.startsWith('^running')) {
      sawResult = true
      runningAwaitingStop = true
      continue
    }
    if (rest.startsWith('^done') || rest.startsWith('^error') || rest.startsWith('^connected')) {
      sawResult = true
      runningAwaitingStop = false
      // 有 stopped 就完整了；没有 stopped 但已经 done，也接受
      if (!runningAwaitingStop) return true
    }
  }
  // `^running` 之后必须等到 `*stopped`：只认 `^running` 会让 `-exec-run` 等到超时
  if (sawResult && runningAwaitingStop) {
    return /(?:^|\n)\*stopped/.test(buffer)
  }
  return false
}

/**
 * 把简化语法翻成 pwntools 桥接认的 JSON。
 *
 * 让 agent 写 `sendline:AAAA` 而不是 `{"op":"sendline","data":"AAAA"}`——
 * 每轮省下的 token 在长会话里累积很可观，而语法只有四条，不会记错。
 */
function encodePwnRequest(command: string): string {
  const idx = command.indexOf(':')
  const op = idx < 0 ? command.trim() : command.slice(0, idx).trim()
  const arg = idx < 0 ? '' : command.slice(idx + 1)
  switch (op) {
    case 'sendline':
      return JSON.stringify({ op: 'sendline', data: arg })
    case 'send':
      return JSON.stringify({ op: 'send', data: arg })
    case 'recv': {
      const n = Number(arg.trim())
      return JSON.stringify(
        Number.isFinite(n) && n > 0 ? { op: 'recv', numb: n } : { op: 'recv' },
      )
    }
    case 'recvuntil':
      // 允许写字面 \n
      return JSON.stringify({ op: 'recvuntil', delim: arg.replace(/\\n/g, '\n') })
    case 'close':
      return JSON.stringify({ op: 'close' })
    default:
      // 认不出的语法原样传，桥接会回 {"ok":false,"error":...}，agent 能看到原因
      return JSON.stringify({ op: op, data: arg })
  }
}

/** pwn 协议：收到一行完整 JSON（且不是启动时的 ready 通知）就算结束。 */
function pwnSettled(buffer: string): boolean {
  for (const raw of buffer.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    if (!line.startsWith('{')) continue
    try {
      const obj = JSON.parse(line) as Record<string, unknown>
      if (obj['ready'] === true) continue
      return true
    } catch {
      continue
    }
  }
  return false
}

/**
 * 把桥接返回的 JSON 折成 agent 读的文本。
 *
 * 保留 `eof` 标记——这是 pwntools 相对 quiet 协议的**主要价值**：
 * 程序已退出和"暂时没输出"是两回事，混淆会让 agent 白等一轮。
 */
function decodePwnResponse(buffer: string): string {
  for (const raw of buffer.split('\n')) {
    const line = raw.trim()
    if (line === '' || !line.startsWith('{')) continue
    try {
      const obj = JSON.parse(line) as Record<string, unknown>
      if (obj['ready'] === true) continue
      if (obj['ok'] === false) return `[session error] ${String(obj['error'] ?? 'unknown')}`
      const out = String(obj['output'] ?? '')
      const marks: string[] = []
      if (obj['eof'] === true) marks.push('EOF')
      if (obj['closed'] === true) marks.push('closed')
      const prefix = marks.length > 0 ? `[${marks.join(' ')}] ` : ''
      return prefix + out
    } catch {
      continue
    }
  }
  return buffer
}

export class SessionManager {
  private readonly sessions = new Map<string, Session>()

  constructor(
    private readonly options: {
      readonly maxSessions?: number
      readonly logDir?: string
    } = {},
  ) {}

  get maxSessions(): number {
    return this.options.maxSessions ?? DEFAULT_MAX_SESSIONS
  }

  start(spec: SessionSpec): Session {
    const live = [...this.sessions.values()].filter((s) => s.info().alive)
    if (live.length >= this.maxSessions) {
      throw new Error(
        `会话数已达上限 ${this.maxSessions}。先 session_stop 掉不用的：` +
          live.map((s) => s.info().id.slice(0, 8)).join(', '),
      )
    }
    const s = new Session(spec, this.options.logDir)
    s.start()
    this.sessions.set(s.id, s)
    return s
  }

  get(id: string): Session | undefined {
    return this.sessions.get(id)
  }

  list(): SessionInfo[] {
    return [...this.sessions.values()].map((s) => s.info())
  }

  async close(id: string): Promise<boolean> {
    const s = this.sessions.get(id)
    if (s === undefined) return false
    await s.close()
    this.sessions.delete(id)
    return true
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.sessions.values()].map((s) => s.close()))
    this.sessions.clear()
  }
}
