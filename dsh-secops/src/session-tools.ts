/**
 * 交互式会话的模型侧工具。
 *
 * ## 为什么是这五个而不是 EnIGMA 的六个
 *
 * EnIGMA 给的是 `debug_start / debug_stop / debug_add_breakpoint / debug_step /
 * debug_continue / debug_exec` —— 针对 gdb 定制的语义命令。这里刻意不这么做：
 * 奶虫的 registry 有 27 个候选，以后还要加，每加一个工具就加一套专用命令会让
 * 工具面爆炸，而模型还得记住每套的语法。
 *
 * 改成**通用会话原语**：start / exec / tail / list / stop。
 * 具体怎么用由领域规格（`agents/*.md`）告诉 agent —— gdb 该先设断点还是先 `starti`，
 * 那是领域知识，不该硬编码在工具签名里。
 *
 * ## 额外加的 session_batch（EnIGMA 没有）
 *
 * 大量场景是"跑一串命令拿结果"，不需要每步都由模型决策。每次往返都要付
 * 一次完整上下文读写的代价。`session_batch` 把"起 → 依次 exec → 收尾"压成一次调用，
 * 只在中间结果需要模型判断时才该改用 `session_exec` 逐步走。
 */

import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { SessionManager, SessionProtocol } from './session-manager.ts'

const SESSION_INFO_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    protocol: { type: 'string' },
    label: { type: 'string' },
    pid: { type: 'number' },
    alive: { type: 'boolean' },
    bytesOut: { type: 'number' },
  },
  required: ['id', 'protocol', 'label', 'alive'],
} as const

const EXEC_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    session_id: { type: 'string' },
    output: { type: 'string' },
    truncated: { type: 'boolean' },
    timed_out: { type: 'boolean' },
    elapsed_ms: { type: 'number' },
    exit_code: { type: 'number' },
  },
  required: ['session_id', 'output', 'truncated', 'timed_out'],
} as const

export interface SessionToolOptions {
  /** 会话日志目录。给了就会把原始流落盘，便于事后核对。 */
  readonly logDir?: string
}

export function sessionTools(
  manager: SessionManager,
  options: SessionToolOptions = {},
): ToolDefinition[] {
  const start: ToolDefinition = {
    name: 'session_start',
    description:
      'Start a long-lived interactive program (debugger, network connection, REPL) that later calls can ' +
      'talk to. Unlike a one-shot command, the process stays alive and its state persists. ' +
      'Use this for gdb, nc/ncat, socat, pwntools-style connections, or any program with a prompt. ' +
      'Return a session id; pass it to session_exec. Up to ' +
      String(manager.maxSessions) +
      ' sessions may be open at once.',
    parameters: {
      type: 'object',
      properties: {
        argv: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Full command line, first element is the executable. For gdb use ["gdb","--interpreter=mi2","-q","./chall"].',
        },
        protocol: {
          type: 'string',
          enum: ['gdb-mi', 'quiet'],
          description:
            '"gdb-mi" for gdb with --interpreter=mi2 (responses are delimited by a protocol token, so they ' +
            'return exactly when the command completes). "quiet" for everything else (returns after output ' +
            'goes silent for idle_ms). Pick gdb-mi whenever the program is gdb.',
        },
        cwd: { type: 'string', description: 'Working directory. Defaults to the current one.' },
        label: { type: 'string', description: 'Short human-readable label for logs.' },
      },
      required: ['argv', 'protocol'],
    },
    output: {
      schema: SESSION_INFO_SCHEMA as unknown as never,
      render: ((_args: unknown, value: unknown) => {
        const o = value as Record<string, unknown>
        return [{ type: 'text', text: `session ${String(o['id'])} started (${String(o['protocol'])}, pid ${String(o['pid'])})` }]
      }) as never,
    },
  } as unknown as ToolDefinition

  const exec: ToolDefinition = {
    name: 'session_exec',
    description:
      'Send one command to an open session and return its output. For gdb-mi, send plain gdb/MI commands ' +
      'WITHOUT a token prefix — the session adds one so responses can be matched exactly ' +
      '(this is why output never gets cut short by a prompt string appearing inside it). ' +
      'The returned output is truncated at max_chars; when that happens, call session_tail for the raw tail.',
    parameters: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        command: { type: 'string', description: 'Command line to send, without trailing newline.' },
        wait_ms: { type: 'number', description: 'Max time to wait for the first byte. Default 10000.' },
        idle_ms: {
          type: 'number',
          description: 'For quiet protocol: how long output must be silent to count as finished. Default 400.',
        },
        max_chars: { type: 'number', description: 'Truncate output beyond this many chars. Default 12000.' },
      },
      required: ['session_id', 'command'],
    },
    output: {
      schema: EXEC_OUTPUT_SCHEMA as unknown as never,
      render: ((_args: unknown, value: unknown) => {
        const o = value as Record<string, unknown>
        const flags = [
          o['timed_out'] === true ? 'TIMED OUT' : '',
          o['truncated'] === true ? 'TRUNCATED' : '',
        ]
          .filter((x) => x !== '')
          .join(' ')
        return [{ type: 'text', text: `${flags === '' ? '' : `[${flags}] `}${String(o['output'])}` }]
      }) as never,
    },
  } as unknown as ToolDefinition

  const batch: ToolDefinition = {
    name: 'session_batch',
    description:
      'Start a session, run a list of commands in order, then close it — all in one call. ' +
      'Use this when you already know the command sequence and do not need to inspect intermediate state. ' +
      'It costs one round trip instead of 2N. If any step needs a decision based on its output, ' +
      'use session_start + session_exec instead.',
    parameters: {
      type: 'object',
      properties: {
        argv: { type: 'array', items: { type: 'string' } },
        protocol: { type: 'string', enum: ['gdb-mi', 'quiet'] },
        commands: {
          type: 'array',
          items: { type: 'string' },
          description: 'Commands to run in order. Each one waits for its own response.',
        },
        cwd: { type: 'string' },
        wait_ms: { type: 'number' },
        idle_ms: { type: 'number' },
        stop_on_error: {
          type: 'boolean',
          description: 'Stop early if a step times out. Default true.',
        },
      },
      required: ['argv', 'protocol', 'commands'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          steps: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                command: { type: 'string' },
                output: { type: 'string' },
                timed_out: { type: 'boolean' },
              },
              required: ['command', 'output', 'timed_out'],
            },
          },
          completed: { type: 'number' },
        },
        required: ['steps', 'completed'],
      } as unknown as never,
      render: ((_args: unknown, value: unknown) => {
        const o = value as Record<string, unknown>
        const steps = (o['steps'] as { command: string; output: string; timed_out: boolean }[]) ?? []
        return [{
          type: 'text',
          text: steps
            .map((st) => `$ ${st.command}\n${st.timed_out ? '[TIMED OUT] ' : ''}${st.output}`)
            .join('\n---\n'),
        }]
      }) as never,
    },
  } as unknown as ToolDefinition

  const tail: ToolDefinition = {
    name: 'session_tail',
    description:
      'Return the last N characters of a session\'s raw output stream. Use after a truncated or timed-out ' +
      'session_exec to see what the program actually printed, including output produced while no command was waiting.',
    parameters: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        chars: { type: 'number', description: 'How many trailing characters. Default 4000.' },
      },
      required: ['session_id'],
    },
    output: {
      schema: {
        type: 'object',
        properties: { output: { type: 'string' }, bytes_out: { type: 'number' } },
        required: ['output'],
      } as unknown as never,
      render: ((_args: unknown, value: unknown) => [
        { type: 'text', text: String((value as Record<string, unknown>)['output']) },
      ]) as never,
    },
  } as unknown as ToolDefinition

  const list: ToolDefinition = {
    name: 'session_list',
    description: 'List open sessions with their id, protocol, pid and whether they are still alive.',
    parameters: { type: 'object', properties: {} },
    output: {
      schema: {
        type: 'object',
        properties: { sessions: { type: 'array', items: SESSION_INFO_SCHEMA } },
        required: ['sessions'],
      } as unknown as never,
      render: ((_args: unknown, value: unknown) => {
        const arr = ((value as Record<string, unknown>)['sessions'] as Record<string, unknown>[]) ?? []
        const text = arr.length === 0
          ? '（没有打开的会话）'
          : arr
              .map(
                (s) =>
                  `${String(s['id']).slice(0, 8)}  ${String(s['protocol'])}  pid=${String(s['pid'])}  ` +
                  `${s['alive'] === true ? 'alive' : 'dead'}  ${String(s['label'])}`,
              )
              .join('\n')
        return [{ type: 'text', text }]
      }) as never,
    },
  } as unknown as ToolDefinition

  const stop: ToolDefinition = {
    name: 'session_stop',
    description: 'Close one session and reap its whole process group (child processes included).',
    parameters: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
    },
    output: {
      schema: {
        type: 'object',
        properties: { closed: { type: 'boolean' } },
        required: ['closed'],
      } as unknown as never,
      render: ((_args: unknown, value: unknown) => [
        {
          type: 'text',
          text: (value as Record<string, unknown>)['closed'] === true ? 'closed' : 'not found',
        },
      ]) as never,
    },
  } as unknown as ToolDefinition

  // ---- 实现绑定 ----
  const bind = (def: ToolDefinition, fn: (input: Record<string, unknown>) => unknown): ToolDefinition =>
    ({ ...(def as unknown as Record<string, unknown>), execute: fn }) as unknown as ToolDefinition

  return [
    bind(start, async (i) => {
      const s = manager.start({
        protocol: i['protocol'] as SessionProtocol,
        argv: i['argv'] as string[],
        cwd: (i['cwd'] as string | undefined) ?? process.cwd(),
        label: i['label'] as string | undefined,
      })
      // pwn 桥接要先等它的 ready 握手，否则第一行响应会读到 ready 而不是命令结果
      await s.waitReady()
      const info = s.info()
      return { ...info, startedAt: undefined }
    }),
    bind(exec, async (i) => {
      const s = manager.get(i['session_id'] as string)
      if (s === undefined) throw new Error(`没有这个会话：${String(i['session_id'])}`)
      const r = await s.exec(i['command'] as string, {
        waitMs: i['wait_ms'] as number | undefined,
        idleMs: i['idle_ms'] as number | undefined,
        maxChars: i['max_chars'] as number | undefined,
      })
      return {
        session_id: i['session_id'],
        output: r.output,
        truncated: r.truncated,
        timed_out: r.timedOut,
        elapsed_ms: r.elapsedMs,
        ...(r.exitCode === null ? {} : { exit_code: r.exitCode }),
      }
    }),
    bind(batch, async (i) => {
      const cmds = i['commands'] as string[]
      const stopOnError = (i['stop_on_error'] as boolean | undefined) ?? true
      const s = manager.start({
        protocol: i['protocol'] as SessionProtocol,
        argv: i['argv'] as string[],
        cwd: (i['cwd'] as string | undefined) ?? process.cwd(),
        label: `batch:${(i['argv'] as string[])[0] ?? '?'}`,
      })
      await s.waitReady()
      const steps: { command: string; output: string; timed_out: boolean }[] = []
      try {
        for (const c of cmds) {
          const r = await s.exec(c, {
            waitMs: i['wait_ms'] as number | undefined,
            idleMs: i['idle_ms'] as number | undefined,
          })
          steps.push({ command: c, output: r.output, timed_out: r.timedOut })
          if (r.timedOut && stopOnError) break
        }
      } finally {
        await manager.close(s.id)
      }
      return { steps, completed: steps.length }
    }),
    bind(tail, (i) => {
      const s = manager.get(i['session_id'] as string)
      if (s === undefined) throw new Error(`没有这个会话：${String(i['session_id'])}`)
      const n = (i['chars'] as number | undefined) ?? 4000
      return { output: s.tail(n), bytes_out: s.info().bytesOut }
    }),
    bind(list, () => ({ sessions: manager.list() })),
    bind(stop, async (i) => ({ closed: await manager.close(i['session_id'] as string) })),
  ]
}
