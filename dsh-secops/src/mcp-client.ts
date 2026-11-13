/**
 * 最小 MCP 客户端（stdio transport）。
 *
 * 存在的理由：一堆强力工具只以 MCP server 的形式存在（CyberStrikeAI、rea、
 * hexstrike）。没有这层，它们永远停在「编译好了但用不上」——
 * 注册表里标个 MISSING 就当交代了，那不是采纳。
 *
 * 只实现真正用得上的四个方法：initialize / notifications/initialized /
 * tools/list / tools/call。MCP 规范里还有 resources / prompts / sampling 等等，
 * 我们一个都不需要——多实现一个就多一份会和上游产生偏差的地方。
 *
 * 协议本身是行分隔的 JSON-RPC 2.0 over stdin/stdout。
 * 日志走 stderr，这一点让 stdout 可以保持纯协议流，不必做任何解析妥协。
 */

import { spawn } from 'node:child_process'
import type { ChildProcessWithoutNullStreams } from 'node:child_process'

export interface McpServerSpec {
  readonly command: readonly string[]
  readonly cwd?: string
  readonly env?: Record<string, string>
  /** 握手 + 每次调用的超时，默认 30 秒。 */
  readonly timeoutMs?: number
}

export interface McpTool {
  readonly name: string
  readonly description?: string
  readonly inputSchema?: unknown
}

export interface McpCallResult {
  /** 文本内容拼起来——绝大多数工具都是这个形态。 */
  readonly text: string
  readonly isError: boolean
  readonly raw: unknown
}

export class McpError extends Error {
  constructor(
    message: string,
    readonly kind: 'spawn' | 'timeout' | 'protocol' | 'rpc' | 'closed',
  ) {
    super(message)
    this.name = 'McpError'
  }
}

interface Pending {
  resolve(value: unknown): void
  reject(error: Error): void
  timer: NodeJS.Timeout
}

const PROTOCOL_VERSION = '2024-11-05'

export class McpStdioClient {
  private readonly spec: Required<Pick<McpServerSpec, 'command' | 'timeoutMs'>> & McpServerSpec
  private child: ChildProcessWithoutNullStreams | undefined
  private buffer = ''
  private nextId = 1
  private readonly pending = new Map<number, Pending>()
  private serverInfo: unknown
  private closed = false

  constructor(spec: McpServerSpec) {
    this.spec = { timeoutMs: 30_000, ...spec }
  }

  /** 启动并握手。idempotent：已连上就直接返回。 */
  async connect(): Promise<void> {
    if (this.child !== undefined) return
    if (this.spec.command.length === 0) throw new McpError('empty command', 'spawn')

    const [cmd, ...args] = this.spec.command
    let child: ChildProcessWithoutNullStreams
    try {
      child = spawn(cmd!, args, {
        ...(this.spec.cwd === undefined ? {} : { cwd: this.spec.cwd }),
        env: { ...process.env, ...(this.spec.env ?? {}) },
        stdio: ['pipe', 'pipe', 'pipe'],
      }) as ChildProcessWithoutNullStreams
    } catch (error) {
      throw new McpError(`spawn failed: ${String(error)}`, 'spawn')
    }
    this.child = child

    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk: string) => this.onData(chunk))
    // stderr 只用于诊断，不进协议流
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', () => {})
    child.on('exit', (code) => this.onExit(code))
    child.on('error', (error) => this.failAll(new McpError(String(error), 'spawn')))

    await this.request('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'dsh-secops', version: '0.1.0' },
    }).then((result) => {
      this.serverInfo = result
    })
    // 握手完成后必须发这条通知，否则部分 server 拒绝继续服务
    this.notify('notifications/initialized', {})
  }

  private onData(chunk: string): void {
    this.buffer += chunk
    let idx = this.buffer.indexOf('\n')
    while (idx !== -1) {
      const line = this.buffer.slice(0, idx).trim()
      this.buffer = this.buffer.slice(idx + 1)
      idx = this.buffer.indexOf('\n')
      if (line === '') continue
      let msg: unknown
      try {
        msg = JSON.parse(line)
      } catch {
        // 有些 server 会往 stdout 打非协议内容；跳过比整体失败合理
        continue
      }
      this.dispatch(msg)
    }
  }

  private dispatch(msg: unknown): void {
    const m = msg as { id?: unknown; result?: unknown; error?: { message?: string; code?: number } }
    if (typeof m.id !== 'number') return // 通知忽略
    const entry = this.pending.get(m.id)
    if (entry === undefined) return
    this.pending.delete(m.id)
    clearTimeout(entry.timer)
    if (m.error !== undefined) {
      entry.reject(new McpError(`rpc error ${String(m.error.code ?? '')}: ${m.error.message ?? 'unknown'}`, 'rpc'))
    } else {
      entry.resolve(m.result)
    }
  }

  private onExit(code: number | null): void {
    this.closed = true
    this.failAll(new McpError(`server exited (code ${String(code)})`, 'closed'))
  }

  private failAll(error: Error): void {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer)
      entry.reject(error)
    }
    this.pending.clear()
  }

  private send(payload: unknown): void {
    const child = this.child
    if (child === undefined || this.closed) throw new McpError('server is not running', 'closed')
    child.stdin.write(`${JSON.stringify(payload)}\n`)
  }

  private notify(method: string, params: unknown): void {
    this.send({ jsonrpc: '2.0', method, params })
  }

  private request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new McpError(`${method} timed out after ${String(this.spec.timeoutMs)}ms`, 'timeout'))
      }, this.spec.timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      try {
        this.send({ jsonrpc: '2.0', id, method, params })
      } catch (error) {
        clearTimeout(timer)
        this.pending.delete(id)
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    })
  }

  async listTools(): Promise<McpTool[]> {
    const result = (await this.request('tools/list', {})) as { tools?: unknown }
    if (!Array.isArray(result.tools)) return []
    return result.tools
      .filter((t): t is Record<string, unknown> => typeof t === 'object' && t !== null)
      .map((t) => ({
        name: String(t['name'] ?? ''),
        ...(typeof t['description'] === 'string' ? { description: t['description'] } : {}),
        ...(t['inputSchema'] === undefined ? {} : { inputSchema: t['inputSchema'] }),
      }))
      .filter((t) => t.name !== '')
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpCallResult> {
    const result = (await this.request('tools/call', { name, arguments: args })) as {
      content?: unknown
      isError?: unknown
    }
    const parts: string[] = []
    if (Array.isArray(result.content)) {
      for (const c of result.content) {
        const item = c as { type?: unknown; text?: unknown }
        if (item.type === 'text' && typeof item.text === 'string') parts.push(item.text)
        else parts.push(JSON.stringify(c))
      }
    }
    return {
      text: parts.join('\n'),
      isError: result.isError === true,
      raw: result,
    }
  }

  get info(): unknown {
    return this.serverInfo
  }

  close(): void {
    this.closed = true
    this.failAll(new McpError('client closed', 'closed'))
    try {
      this.child?.stdin.end()
      this.child?.kill()
    } catch {
      /* 已经退出 */
    }
    this.child = undefined
  }
}

/** 一次性用法：连上、列工具、断开。用于探测一个 server 能干什么。 */
export async function probeMcpServer(spec: McpServerSpec): Promise<{ tools: McpTool[]; serverInfo: unknown }> {
  const client = new McpStdioClient(spec)
  try {
    await client.connect()
    const tools = await client.listTools()
    return { tools, serverInfo: client.info }
  } finally {
    client.close()
  }
}
