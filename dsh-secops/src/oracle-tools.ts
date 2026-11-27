/**
 * 实证预言机工具：把"跑一遍"变成能进证据链的事实。
 *
 * 这个工具与 claim_evidence 的分工：
 *
 *   claim_evidence —— 模型已经跑过了，把产物文件拿来登记
 *   oracle_run     —— 模型给命令和期望，**由系统跑**，再由系统判定
 *
 * 后者更硬，因为 argv 和输出都是系统产生的，模型只能提供"打哪里、什么算通"。
 * 这也是为什么这类证据能拿到 `executedTrusted`——那一位的唯一含义是
 * "argv 来自系统记录"，而这里它确实是。
 *
 * 一条纪律写进了输出：`unknown` 不是 `miss`。超时、OOM、supervisor 不可用
 * 都不能读成"漏洞不存在"，它们只是没测成。
 */

import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { ClaimStore } from './provenance-tools.ts'
import { findRunner, judge, readLog, runInSandbox } from './oracle.ts'
import type { Expectation } from './oracle.ts'

const RUN_SCHEMA = {
  type: 'object',
  properties: {
    claim_id: { type: 'string' },
    outcome: { type: 'string' },
    reason: { type: 'string' },
    status: { type: 'string' },
    exit: { type: 'number' },
    elapsed_ms: { type: 'number' },
    peak_mem_kb: { type: 'number' },
    timed_out: { type: 'boolean' },
    kill_reason: { type: 'string' },
    oom_kill: { type: 'number' },
    supervised: { type: 'boolean' },
    log_path: { type: 'string' },
    log_tail: { type: 'string' },
    evidence_ref: { type: 'string' },
    rejected: { type: 'string' },
  },
  required: ['claim_id', 'outcome', 'reason', 'status'],
} as const

export interface OracleToolsOptions {
  /** nai-run 路径；不给就自动找。 */
  readonly runnerPath?: string
  /** 默认内存上限。给一个默认值而不是不设限——没上限的沙箱只是普通进程。 */
  readonly defaultMem?: string
  readonly defaultTimeoutSec?: number
}

/** 把扁平参数还原成判定用的 Expectation。 */
function toExpectation(a: Record<string, unknown>): Expectation | null {
  const type = a['type']
  switch (type) {
    case 'exit-code':
      return {
        type: 'exit-code',
        ...(typeof a['exact'] === 'number' ? { exact: a['exact'] } : {}),
        ...(typeof a['nonZero'] === 'boolean' ? { nonZero: a['nonZero'] } : {}),
      }
    case 'output-contains':
      return typeof a['text'] === 'string' ? { type: 'output-contains', text: a['text'] } : null
    case 'output-matches':
      return typeof a['pattern'] === 'string' ? { type: 'output-matches', pattern: a['pattern'] } : null
    case 'canary':
      return typeof a['token'] === 'string' ? { type: 'canary', token: a['token'] } : null
    case 'sanitizer':
      return {
        type: 'sanitizer',
        ...(typeof a['kind'] === 'string' ? { kind: a['kind'] as 'address' | 'memory' | 'undefined' | 'thread' } : {}),
      }
    default:
      return null
  }
}

export function oracleTools(store: ClaimStore, opts: OracleToolsOptions = {}): ToolDefinition[] {
  const runner = opts.runnerPath ?? findRunner()

  const runTool: ToolDefinition = {
    name: 'oracle_run',
    description:
      'Run a reproduction command INSIDE THE SANDBOX (cgroup memory cap, wall-clock and no-output timeouts, ' +
      'process-tree cleanup) and let the system judge the result against an expectation you declare. ' +
      'Unlike claim_evidence, here the argv and the output are produced by the system, so the resulting evidence ' +
      'can count toward confirmation. ' +
      'You must declare what counts as success: an exit code, a substring, a regex, or a canary token that only ' +
      'the target could have returned (strongest). ' +
      'IMPORTANT: the argv must itself touch the claim anchors (the route path, the parameter name) — the system ' +
      'checks evidence relevance against what was actually executed, so a command that never mentions the endpoint ' +
      'cannot become evidence for it, no matter what its output says. ' +
      'The outcome is one of hit / miss / unknown. UNKNOWN IS NOT MISS: a timeout, an OOM kill, or a missing ' +
      'sandbox means the test did not run to completion, and must never be reported as "not vulnerable".',
    parameters: {
      type: 'object',
      properties: {
        claim_id: { type: 'string', description: 'Claim this run is evidence for or against.' },
        argv: {
          type: 'array',
          items: { type: 'string' },
          description: 'Command and arguments to execute, e.g. ["curl","-s","-i","http://127.0.0.1:8080/api/x"]. No shell interpolation.',
        },
        expect: {
          type: 'object',
          description: 'What counts as a hit.',
          properties: {
            type: { type: 'string', enum: ['exit-code', 'output-contains', 'output-matches', 'canary', 'sanitizer'] },
            kind: { type: 'string', enum: ['address', 'memory', 'undefined', 'thread'], description: 'For sanitizer: which sanitizer report you expect.' },
            exact: { type: 'number', description: 'For exit-code: the exact code expected.' },
            nonZero: { type: 'boolean', description: 'For exit-code: expect any non-zero exit.' },
            text: { type: 'string', description: 'For output-contains: substring that must appear.' },
            pattern: { type: 'string', description: 'For output-matches: JS regex that must match.' },
            token: { type: 'string', description: 'For canary: the random token the target must have returned.' },
          },
          required: ['type'],
        },
        timeout_sec: { type: 'number', description: 'Wall-clock cap (default 60).' },
        mem: { type: 'string', description: 'Memory cap such as "256M". Defaults to the configured limit.' },
        cwd: { type: 'string', description: 'Working directory.' },
        note: { type: 'string', description: 'What this run is trying to prove.' },
      },
      required: ['claim_id', 'argv', 'expect'],
    },
    output: {
      schema: RUN_SCHEMA as unknown as never,
      render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
    },
    execute: async (args: unknown) => {
      const a = (args ?? {}) as Record<string, unknown>
      const claimId = typeof a['claim_id'] === 'string' ? a['claim_id'] : ''
      const claim = store.get(claimId)
      const status0 = claim?.status ?? 'unknown'

      if (claim === undefined) {
        return { claim_id: claimId, outcome: 'unknown', reason: 'unknown claim', status: status0 }
      }
      const argv = Array.isArray(a['argv']) ? (a['argv'] as unknown[]).filter((x): x is string => typeof x === 'string') : []
      if (argv.length === 0) {
        return { claim_id: claimId, outcome: 'unknown', reason: 'argv is empty', status: status0 }
      }
      const expectRaw = (a['expect'] ?? {}) as Record<string, unknown>
      const expect = toExpectation(expectRaw)
      if (expect === null) {
        return {
          claim_id: claimId,
          outcome: 'unknown',
          reason: 'expect is missing or malformed; declare what counts as success before running',
          status: status0,
        }
      }
      if (runner === null) {
        return {
          claim_id: claimId,
          outcome: 'unknown',
          reason: 'sandbox runner (nai-run) not found — refusing to run uncontained; build engine/runner or set NAI_RUN',
          status: status0,
        }
      }

      const result = await runInSandbox({
        runnerPath: runner,
        argv,
        timeoutSec: typeof a['timeout_sec'] === 'number' ? a['timeout_sec'] : (opts.defaultTimeoutSec ?? 60),
        mem: typeof a['mem'] === 'string' ? a['mem'] : (opts.defaultMem ?? '512M'),
        ...(typeof a['cwd'] === 'string' ? { cwd: a['cwd'] } : {}),
      })

      const logText = readLog(result.log_path)
      const verdict = judge(result, expect, logText)

      const base = {
        claim_id: claimId,
        outcome: verdict.outcome,
        reason: verdict.reason,
        exit: result.exit,
        elapsed_ms: result.elapsed_ms,
        peak_mem_kb: result.peak_mem_kb,
        timed_out: result.timed_out,
        kill_reason: result.kill_reason,
        oom_kill: result.oom_kill,
        supervised: result.supervised,
        log_path: result.log_path,
        log_tail: logText.slice(-600),
      }

      // unknown 不入库：环境故障不构成任何方向上的证据
      if (verdict.outcome === 'unknown') {
        return { ...base, status: store.get(claimId)?.status ?? status0, evidence_ref: '' }
      }

      const ref = `oracle:${argv.slice(0, 2).join(' ')}`
      const pathKey = `oracle:${typeof a['note'] === 'string' && a['note'] !== '' ? a['note'] : verdict.outcome}`
      const executed = argv.join(' ')

      let rejected = ''
      if (verdict.outcome === 'hit') {
        const res = store.attach(claimId, {
          ref,
          pathKey,
          executed,
          executedTrusted: true,
          artifact: logText.slice(-8000),
          artifactTrusted: true,
          ...(typeof a['note'] === 'string' ? { note: a['note'] } : {}),
        })
        if (!res.ok) rejected = res.reason ?? 'evidence rejected'
        return {
          ...base,
          status: store.get(claimId)?.status ?? status0,
          evidence_ref: res.ok ? ref : '',
          ...(rejected === '' ? {} : { rejected }),
        }
      }

      // miss：跑通了但没打通。作为反驳线索入库，但**不自动判死**——
      // 可能是 payload 不对、前置条件没满足，而不是漏洞不存在。
      const res = store.attach(claimId, {
        ref,
        pathKey,
        executed,
        executedTrusted: true,
        artifact: logText.slice(-8000),
        artifactTrusted: true,
        role: 'refutation',
        refutation: {
          kind: 'advisory',
          check: 'empirical-miss',
          detail: `reproduction ran to completion (exit ${String(result.exit)}) but the declared expectation was not met: ${verdict.reason}`,
        },
        ...(typeof a['note'] === 'string' ? { note: a['note'] } : {}),
      })
      if (!res.ok) rejected = res.reason ?? 'evidence rejected'
      return {
        ...base,
        status: store.get(claimId)?.status ?? status0,
        evidence_ref: res.ok ? ref : '',
        ...(rejected === '' ? {} : { rejected }),
      }
    },
  }

  return [runTool]
}
