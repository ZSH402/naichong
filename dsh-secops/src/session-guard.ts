/**
 * 交互式工具的使用护栏。
 *
 * ## 拦的是什么
 *
 * `gdb ./chall` 这样裸跑会**阻塞到超时**：gdb 进了 REPL 就不再返回，而 runner 拿不到
 * 退出码，只能等到超时被 SIGKILL。这一轮的时间和输出全废。
 *
 * EnIGMA 明确记录了这个坑，并在 SWE-agent 里加了护栏：检测到裸跑 gdb 就打印警告，
 * 引导 agent 用交互接口。这里做同样的事。
 *
 * ## 为什么只提醒不拒绝
 *
 * 有些 gdb 用法确实是合法的一次性调用：`gdb --version`、`gdb -batch -ex 'info files'`。
 * 更关键的是，**拒绝会让 agent 卡死**——它不知道还能怎么办。提醒则把选择权留给它，
 * 同时把"为什么不该这么做"说清楚。
 *
 * 这条判据刻意保守：宁可漏报（让它超时一次自己学会），也不要误报打断一次合法的
 * batch 调试。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import { randomUUID } from 'node:crypto'

/** 明确安全的 gdb 用法：批处理模式、或只是查版本/帮助。 */
const SAFE_GDB = /--interpreter[= ]mi\d?|-batch\b|--batch\b|-ex\b|--eval-command|-x\b|--command\b/

/** 无害的查询，不构成阻塞风险。 */
const HARMLESS_QUERY = /--version|--help|\bwhich\s+gdb\b|\bcommand\s+-v\s+gdb\b|\btype\s+gdb\b/

/**
 * 判断一条命令是否会因为裸跑 gdb 而阻塞。
 *
 * 只认「命令里出现 gdb 可执行文件」这一种形态；`strings binary | grep gdb` 这类
 * 提到 gdb 字样的不算——那是文本搜索，不会启动 gdb。
 */
export function looksLikeBlockingGdb(command: string): boolean {
  // 必须是以 gdb 开头的一段（行首，或 ; | && || 之后），才算真的启动了 gdb
  const startsGdb = /(?:^|[;&|]\s*|\bthen\s+|\bdo\s+)(?:sudo\s+)?(?:\S*python\S*\s+-\S+\s+)?gdb\b/.test(command)
  if (!startsGdb) return false
  if (SAFE_GDB.test(command)) return false
  if (HARMLESS_QUERY.test(command)) return false
  return true
}

export function blockingGdbReminder(): string {
  return (
    '[secops/session] 你刚才启动了一个**会阻塞的 gdb**：它会进入 REPL 而不返回，' +
    '这一轮只能等到超时被 SIGKILL，输出全丢。\n\n' +
    '改用交互式会话，它把 gdb 作为长驻进程管理，每条命令都有精确的响应定界：\n\n' +
    '  session_start  { argv: ["gdb","--interpreter=mi2","-q","./chall"], protocol: "gdb-mi" }\n' +
    '  session_exec   { session_id: "…", command: "-break-insert main" }\n' +
    '  session_exec   { session_id: "…", command: "-exec-run" }\n' +
    '  session_exec   { session_id: "…", command: "-data-evaluate-expression \\"$rdi\\"" }\n\n' +
    '如果确实只需要一次性拿信息，用 batch 模式（不会阻塞）：\n' +
    '  gdb -batch -ex "info functions" -ex "quit" ./chall\n' +
    '或者一次跑完多步：session_batch { argv: […], protocol: "gdb-mi", commands: [ … ] }'
  )
}

export interface SessionGuardOptions {
  readonly logger?: {
    info(msg: string): void
    warn(msg: string): void
  }
}

export interface SessionGuardStats {
  readonly nudges: number
  readonly calls: number
}

/**
 * 挂上护栏。返回取统计的句柄，供卸载时打一行日志。
 */
export function installSessionGuard(
  ctx: Context,
  options: SessionGuardOptions = {},
): { stats(): SessionGuardStats } {
  let pending: string | undefined
  let nudges = 0
  let calls = 0
  const hits: string[] = []

  const userMessage = (text: string): UserMessage => ({
    id: randomUUID() as UserMessage['id'],
    role: 'user',
    source: { kind: 'user' },
    content: [{ type: 'text', text }],
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    calls += 1
    // 只关心执行命令的工具；session_exec 本身就是正解，不会被判成阻塞
    const name = typeof exec.name === 'string' ? exec.name : ''
    const args = exec.arguments as { command?: unknown } | undefined
    const cmd = typeof args?.command === 'string' ? args.command : undefined
    if (cmd !== undefined && name !== 'session_exec' && looksLikeBlockingGdb(cmd)) {
      if (pending === undefined) {
        pending = blockingGdbReminder()
        hits.push(cmd.slice(0, 120))
        options.logger?.warn(`secops/session: 检测到阻塞式 gdb 调用，将提示改用交互会话`)
      }
    }
    return next()
  })

  ctx.on('agent/pre-step', async (payload, next): Promise<PreStepDecision> => {
    const decision = await next()
    if (pending === undefined) return decision
    if (decision.kind !== 'enter') return decision
    const note = pending
    pending = undefined
    nudges += 1
    options.logger?.info(`secops/session: 已注入交互会话引导（第 ${String(nudges)} 次）`)
    return { kind: 'enter', messages: [...decision.messages, userMessage(note)] }
  })

  return {
    stats: () => ({ nudges, calls }),
  }
}
