/**
 * 出口代理：唯一被授权的出站通道。
 *
 * 为什么需要它：`--unshare-net` 能彻底断网，但 worker 也就没法扫描了。
 * 正确形态是「断掉直连 + 只留一条受控通道」：
 *   - worker 跑在独立 netns 里，只有 loopback
 *   - 宿主上的本代理通过 unix socket 暴露（bwrap 绑进 netns）
 *   - worker 内用 socat 把 unix socket 转成 127.0.0.1 上的 TCP 代理
 *   - 只有 HTTP_PROXY 指向它，代理按 allowlist 放行
 *
 * 这样越界请求有两道拦截：netns 断直连（内核层）、代理拒目标（应用层）。
 * 只做代理不做 netns 是纸糊的 —— worker 直接 socket() 就绕过去了。
 */

import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'

export interface EgressProxyOptions {
  /** 授权目标 host（精确匹配，大小写不敏感）。 */
  readonly allowedHosts: readonly string[]
  /** unix socket 路径。 */
  readonly socketPath: string
  /** 每次判定都回调，用于落证据。 */
  readonly onDecision?: (decision: {
    readonly host: string
    readonly port: number
    readonly allowed: boolean
    readonly at: number
  }) => void
}

interface Tunnel {
  readonly client: net.Socket
  readonly upstream?: net.Socket
}

/** 只接受 host:port，拒绝任何畸形目标 —— 畸形即拒绝，不做宽容解析。 */
function parseTarget(authority: string, defaultPort: number): { host: string; port: number } | undefined {
  const trimmed = authority.trim()
  if (trimmed.length === 0) return undefined
  // CONNECT 形式：host:port
  const m = /^([A-Za-z0-9.\-:[\]]+?):(\d{1,5})$/.exec(trimmed)
  if (m !== null) {
    const port = Number(m[2])
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return undefined
    return { host: m[1]!.replace(/^\[|\]$/g, '').toLowerCase(), port }
  }
  if (/^[A-Za-z0-9.\-[\]]+$/.test(trimmed)) {
    return { host: trimmed.replace(/^\[|\]$/g, '').toLowerCase(), port: defaultPort }
  }
  return undefined
}

export class EgressProxy {
  private readonly allowed: Set<string>
  private readonly socketPath: string
  private readonly onDecision: EgressProxyOptions['onDecision']
  private server: http.Server | undefined
  private readonly tunnels = new Set<Tunnel>()

  constructor(options: EgressProxyOptions) {
    this.allowed = new Set(options.allowedHosts.map((h) => h.trim().toLowerCase()))
    this.socketPath = options.socketPath
    this.onDecision = options.onDecision
  }

  get listening(): boolean {
    return this.server !== undefined
  }

  async start(): Promise<void> {
    if (this.server !== undefined) return
    fs.mkdirSync(path.dirname(this.socketPath), { recursive: true })
    if (fs.existsSync(this.socketPath)) fs.unlinkSync(this.socketPath)

    const server = http.createServer()
    server.on('request', (req, res) => this.handleRequest(req, res))
    server.on('connect', (req, socket, head) => this.handleConnect(req, socket as net.Socket, head))

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.socketPath, () => resolve())
    })
    this.server = server
    // unix socket 只给本用户用
    try {
      fs.chmodSync(this.socketPath, 0o600)
    } catch {
      /* best effort */
    }
  }

  async stop(): Promise<void> {
    for (const t of this.tunnels) {
      t.client.destroy()
      t.upstream?.destroy()
    }
    this.tunnels.clear()
    const server = this.server
    this.server = undefined
    if (server === undefined) return
    await new Promise<void>((resolve) => server.close(() => resolve()))
    try {
      fs.unlinkSync(this.socketPath)
    } catch {
      /* already gone */
    }
  }

  private decide(host: string, port: number): boolean {
    const allowed = this.allowed.size === 0 ? false : this.allowed.has(host)
    this.onDecision?.({ host, port, allowed, at: Date.now() })
    return allowed
  }

  /** CONNECT：HTTPS 隧道。 */
  private handleConnect(req: http.IncomingMessage, client: net.Socket, head: Buffer): void {
    const target = parseTarget(req.url ?? '', 443)
    if (target === undefined || !this.decide(target.host, target.port)) {
      client.end('HTTP/1.1 403 Forbidden\r\nX-Secops-Egress: denied\r\n\r\n')
      return
    }
    const upstream = net.connect(target.port, target.host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head.length > 0) upstream.write(head)
      upstream.pipe(client)
      client.pipe(upstream)
    })
    const tunnel: Tunnel = { client, upstream }
    this.tunnels.add(tunnel)
    const cleanup = (): void => {
      this.tunnels.delete(tunnel)
      upstream.destroy()
      client.destroy()
    }
    upstream.on('error', cleanup)
    client.on('error', cleanup)
    client.on('close', cleanup)
    upstream.on('close', cleanup)
  }

  /**
   * 普通 HTTP 代理请求（`GET http://host/path`）。
   *
   * 只支持明文 http；https 一律走 CONNECT。畸形 URL 直接拒绝。
   */
  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    let url: URL
    try {
      url = new URL(req.url ?? '')
    } catch {
      res.writeHead(400, { 'X-Secops-Egress': 'malformed' }).end('bad request target')
      return
    }
    const host = url.hostname.toLowerCase()
    const port = url.port === '' ? 80 : Number(url.port)
    if (!this.decide(host, port)) {
      res.writeHead(403, { 'X-Secops-Egress': 'denied' }).end('egress denied')
      return
    }
    const upstreamReq = http.request(
      {
        host,
        port,
        method: req.method,
        path: `${url.pathname}${url.search}`,
        headers: { ...req.headers, host: url.host },
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers)
        upstreamRes.pipe(res)
      },
    )
    upstreamReq.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { 'X-Secops-Egress': 'upstream-error' })
      res.end()
    })
    req.pipe(upstreamReq)
  }
}
