/**
 * 网络命名空间包裹：把一条外部命令关进只有 loopback 的 netns，
 * 再把出口代理的 unix socket 绑进去，使代理成为唯一出站通道。
 *
 * 实测约束（本机验证）：
 *   - `/run` 与 `/tmp` 在 `--ro-bind / /` 下都不可直接 mkdir，
 *     必须先 `--tmpfs <dir>` 再 `--bind <socket> <dir>/<name>`
 *   - `/run` 比 `/tmp` 更适合放代理 socket（不干扰被测命令对 /tmp 的使用）
 *   - `--unshare-net` 确实断掉所有非 loopback 出站（基线 200 → 000）
 */

import fs from 'node:fs'

/** 默认代理端口（netns 内的 loopback）。 */
export const NETNS_PROXY_PORT = 3128
/** 代理 socket 在 netns 内的挂载点。 */
export const NETNS_PROXY_PATH = '/run/secops-egress.sock'

export interface NetnsWrapOptions {
  readonly argv: readonly string[]
  /** 被测命令的工作目录；会以读写方式 bind 进 netns。 */
  readonly workdir: string
  /** 宿主上的代理 unix socket 路径。 */
  readonly proxySocket: string
  /** 额外可写目录。 */
  readonly writableRoots?: readonly string[]
  readonly proxyPort?: number
  readonly extraEnv?: Record<string, string>
}

/**
 * 生成 bwrap 包裹后的完整 argv。
 *
 * 不在这里 spawn：调用方（队列执行器）保留对进程组、超时、证据的控制权。
 */
export function netnsCommand(options: NetnsWrapOptions): string[] {
  const port = options.proxyPort ?? NETNS_PROXY_PORT
  const proxyUrl = `http://127.0.0.1:${port}`

  const args: string[] = [
    'bwrap',
    '--unshare-net',
    '--ro-bind', '/', '/',
    '--dev', '/dev',
    '--proc', '/proc',
    '--tmpfs', '/tmp',
    '--tmpfs', '/run',
    // 代理 socket 必须先于 workdir 绑定，否则会被 /tmp 的 tmpfs 遮住
    '--bind', options.proxySocket, NETNS_PROXY_PATH,
    '--bind', options.workdir, options.workdir,
  ]

  for (const root of options.writableRoots ?? []) {
    args.push('--bind', root, root)
  }

  args.push('--die-with-parent')

  const env: Record<string, string> = {
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    ALL_PROXY: proxyUrl,
    all_proxy: proxyUrl,
    NO_PROXY: 'localhost,127.0.0.1,::1',
    no_proxy: 'localhost,127.0.0.1,::1',
    ...options.extraEnv,
  }
  for (const [k, v] of Object.entries(env)) args.push('--setenv', k, v)

  // socat 把 unix socket 转成 netns 内的 loopback TCP，后台起好再 exec 真命令。
  const script =
    `socat TCP-LISTEN:${port},fork,reuseaddr UNIX-CONNECT:${NETNS_PROXY_PATH} >/dev/null 2>&1 & ` +
    `exec "$@"`

  args.push('--', 'sh', '-c', script, 'sh', ...options.argv)
  return args
}

/** 判断本机是否具备 netns 隔离的运行前提。 */
export function netnsAvailable(): boolean {
  return requireBin('bwrap') && requireBin('socat')
}

function requireBin(bin: string): boolean {
  for (const dir of (process.env.PATH ?? '').split(':')) {
    if (dir.length === 0) continue
    try {
      if (fs.existsSync(`${dir}/${bin}`)) return true
    } catch {
      /* ignore */
    }
  }
  return false
}
