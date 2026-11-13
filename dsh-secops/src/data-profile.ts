/**
 * 数据画像：拿到任何一份东西，先量它的形状，再决定怎么分析。
 *
 * 这条不是为某类题做的，是为一个反复出现的行为模式做的：
 * 模型拿到数据就直接开始写解析器，解析器写错了却不知道，然后在错误的模型上
 * 推论几小时。真实渗透里同样的路径代价更大——漏报会写成「目标没有这个漏洞」，
 * 误报会变成一条经不起复核的 finding。
 *
 * 量形状是廉价的、几乎不可能错的，而且它常常直接给出判断：
 *   「这份东西有 5 万行、每行都是 A -> B」→ 是关系图，不是日志
 *   「这份东西 99% 的行都在 12 个不同模板里」→ 是模板生成的，先归类再解析
 *   「这份东西一半是二进制」→ 不要用文本工具硬啃
 * 有了这些，模型才有可能在写第一行解析代码之前，先问一句「我理解对了吗」。
 */

import fs from 'node:fs'
import path from 'node:path'
import type { JsonSchemaNode, ToolDefinition } from '@deepseek-ai/dsh-tools'

export type DataKind = 'empty' | 'json' | 'csv' | 'key-value' | 'rule-graph' | 'log-lines' | 'binary' | 'text'

export interface FieldStat {
  readonly value: string
  readonly count: number
}

export interface DataProfile {
  readonly path: string
  readonly bytes: number
  readonly lines: number
  readonly kind: DataKind
  /** 判定依据，说明为什么认为是这一类。 */
  readonly why: string
  /** 每行字段数的分布（前 3 种）。 */
  readonly fieldCounts: readonly FieldStat[]
  /** 重复行比例：高说明数据是模板生成的，解析前应先归类。 */
  readonly duplicateRatio: number
  /** 高频首 token，用来判断行模板。 */
  readonly topPrefixes: readonly FieldStat[]
  /** 分隔符猜测。 */
  readonly delimiter?: string
  /** 二进制/非 UTF-8 字节比例。 */
  readonly nonTextRatio: number
  /** 明显偏长的行（可能是打包数据或 base64）。 */
  readonly longestLine: number
  /** 一句话结论。 */
  readonly verdict: string
}

const MAX_READ = 32 * 1024 * 1024

function guessDelimiter(line: string): string | undefined {
  for (const d of [',', '\t', '|', ';']) {
    if (line.includes(d)) return d === '\t' ? 'tab' : d
  }
  return undefined
}

/**
 * 主导行形状的粗归类。
 *
 * 只看结构不看语义——语义是模型的事，形状是这里能确定回答的。
 */
function classify(lines: readonly string[], nonTextRatio: number): { kind: DataKind; why: string } {
  if (lines.length === 0) return { kind: 'empty', why: 'no non-empty lines' }
  if (nonTextRatio > 0.05) {
    return { kind: 'binary', why: `${Math.round(nonTextRatio * 100)}% of bytes are not printable text` }
  }

  const sample = lines.slice(0, 200)
  const first = sample[0] ?? ''
  const trimmed = first.trim()

  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || trimmed.startsWith('[')) {
    try {
      JSON.parse(lines.join('\n'))
      return { kind: 'json', why: 'whole file parses as one JSON document' }
    } catch {
      // 可能是 JSONL
      const jsonl = sample.filter((l) => {
        const t = l.trim()
        return t.startsWith('{') && t.endsWith('}')
      })
      if (jsonl.length > sample.length * 0.9) {
        return { kind: 'json', why: 'one JSON object per line (JSONL)' }
      }
    }
  }

  const arrow = sample.filter((l) => l.includes('->')).length
  if (arrow > sample.length * 0.8) {
    return { kind: 'rule-graph', why: `${String(arrow)}/${String(sample.length)} sampled lines contain "->"` }
  }

  const delimited = sample.filter((l) => /[,;\t|]/.test(l)).length
  if (delimited > sample.length * 0.8) return { kind: 'csv', why: 'most lines contain a consistent delimiter' }

  const kv = sample.filter((l) => /^[\w.-]+\s*[:=]\s*\S/.test(l.trim())).length
  if (kv > sample.length * 0.7) return { kind: 'key-value', why: 'most lines look like key: value' }

  const timePrefixed = sample.filter((l) => /^\[?\d{4}-\d{2}-\d{2}|^\d{2}:\d{2}:\d{2}/.test(l.trim())).length
  if (timePrefixed > sample.length * 0.3) return { kind: 'log-lines', why: 'many lines start with a timestamp' }

  return { kind: 'text', why: 'free-form lines, no consistent structure detected' }
}

export function profileData(filePath: string): DataProfile | undefined {
  let buf: Buffer
  try {
    const stat = fs.statSync(filePath)
    const fd = fs.openSync(filePath, 'r')
    try {
      const size = Math.min(stat.size, MAX_READ)
      buf = Buffer.allocUnsafe(size)
      fs.readSync(fd, buf, 0, size, 0)
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    return undefined
  }

  const bytes = buf.length
  let nonText = 0
  for (const b of buf) {
    // 允许换行/制表/可打印 ASCII/多字节 UTF-8 高位
    if (b === 0x0a || b === 0x0d || b === 0x09) continue
    if (b < 0x20 || b === 0x7f) nonText += 1
  }
  const nonTextRatio = bytes === 0 ? 0 : nonText / bytes

  const text = buf.toString('utf8')
  const rawLines = text.split('\n')
  const lines = rawLines.map((l) => l.replace(/\r$/, '')).filter((l) => l.trim() !== '')

  const { kind, why } = classify(lines, nonTextRatio)

  const fieldCount = new Map<string, number>()
  const prefix = new Map<string, number>()
  const seen = new Map<string, number>()
  let longest = 0
  for (const line of lines.slice(0, 20000)) {
    const t = line.trim()
    longest = Math.max(longest, line.length)
    const tok = t.split(/[\s,:=\->]+/)[0] ?? ''
    if (tok.length > 0) prefix.set(tok, (prefix.get(tok) ?? 0) + 1)
    const delim = guessDelimiter(line)
    const n = delim === undefined ? 1 : line.split(delim === 'tab' ? '\t' : delim).length
    fieldCount.set(String(n), (fieldCount.get(String(n)) ?? 0) + 1)
    // 归一化后再比：日志和导出数据几乎每行都有不同的数字/时间戳/ID，
    // 按字面比会把「同一个模板生成的一万行」算成零重复，
    // 而这类数据恰恰最该先归类再解析。
    seen.set(t.replace(/[0-9a-f]{8,}/gi, '#').replace(/\d+/g, '#'), (seen.get(t) ?? 0) + 1)
  }
  const sampled = Math.min(lines.length, 20000)
  const unique = seen.size
  const duplicateRatio = sampled === 0 ? 0 : 1 - unique / sampled

  const top = (m: Map<string, number>, n: number): FieldStat[] =>
    [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([value, count]) => ({ value: value.length > 40 ? `${value.slice(0, 37)}...` : value, count }))

  const delimiter = kind === 'csv' ? guessDelimiter(lines[0] ?? '') : undefined

  const hints: string[] = []
  if (duplicateRatio > 0.5) hints.push(`重复行占 ${Math.round(duplicateRatio * 100)}%，先归类模板再看内容`)
  if (longest > 5000) hints.push(`最长行 ${String(longest)} 字符，可能内嵌打包数据`)
  if (kind === 'binary') hints.push('以二进制为主，别用文本工具硬啃')
  if (kind === 'rule-graph') hints.push('是关系/规则图：先看连通性和层数，再谈求解')

  const verdict =
    `${String(lines.length)} 行 / ${String(bytes)} 字节，判定为 ${kind}（${why}）` +
    (hints.length === 0 ? '' : `；${hints.join('；')}`)

  return {
    path: filePath,
    bytes,
    lines: lines.length,
    kind,
    why,
    fieldCounts: top(fieldCount, 3),
    duplicateRatio,
    topPrefixes: top(prefix, 5),
    ...(delimiter === undefined ? {} : { delimiter }),
    nonTextRatio,
    longestLine: longest,
    verdict,
  }
}

export { MAX_READ as PROFILE_MAX_READ }

/** 只是给调用方省一次拼路径。 */
export function profilePath(p: string): DataProfile | undefined {
  return profileData(path.resolve(p))
}

// ── 模型侧工具 ───────────────────────────────────────────────

const PROFILE_SCHEMA: JsonSchemaNode = {
  type: 'object',
  properties: {
    kind: { type: 'string', description: 'empty | json | csv | key-value | rule-graph | log-lines | binary | text' },
    lines: { type: 'number' },
    bytes: { type: 'number' },
    why: { type: 'string', description: 'Why this classification was chosen.' },
    verdict: { type: 'string' },
    duplicate_ratio: { type: 'number' },
    delimiter: { type: 'string' },
    non_text_ratio: { type: 'number' },
    longest_line: { type: 'number' },
    field_counts: { type: 'array', items: { type: 'object', properties: { value: { type: 'string' }, count: { type: 'number' } }, required: ['value', 'count'] } },
    top_prefixes: { type: 'array', items: { type: 'object', properties: { value: { type: 'string' }, count: { type: 'number' } }, required: ['value', 'count'] } },
  },
  required: ['kind', 'lines', 'bytes', 'verdict'],
}

/**
 * 画像工具。
 *
 * 描述里写明「写任何解析器之前先跑这个」——真实故障就是反过来的：
 * 先写解析代码，解析器有 bug 却不知道，然后在错误模型上推论几小时。
 * 真实渗透里同样的路径会变成漏报（「目标没有这个漏洞」）或误报。
 */
export function dataProfileTools(options: { readonly onProfile?: (p: DataProfile) => void } = {}): ToolDefinition[] {
  return [
    {
      name: 'profile_data',
      description:
        'Measure the shape of a file before writing any parser for it. Reports line/byte counts, whether it is JSON / CSV / ' +
        'key-value / a rule graph / logs / binary, delimiter, duplicate-line ratio, top line prefixes, and the longest line. ' +
        'Run this first: parsing on a wrong assumption about the format is the most common way an analysis silently produces ' +
        'a wrong conclusion — and in a security assessment that becomes a missed finding or a false report. Cheap, and ' +
        'almost impossible to get wrong.',
      parameters: {
        type: 'object',
        properties: { path: { type: 'string', description: 'File to profile.' } },
        required: ['path'],
      },
      output: {
        schema: PROFILE_SCHEMA,
        render: (_a: unknown, v: unknown) => {
          const r = v as Record<string, unknown>
          return [
            {
              type: 'text',
              text: [
                `kind=${String(r.kind)} lines=${String(r.lines)} bytes=${String(r.bytes)}`,
                `why: ${String(r.why)}`,
                `duplicate_ratio=${String(r.duplicate_ratio)} longest_line=${String(r.longest_line)}${r.delimiter === undefined ? '' : ` delimiter=${String(r.delimiter)}`}`,
                `verdict: ${String(r.verdict)}`,
              ].join('\n'),
            },
          ]
        },
      },
      async execute(args: Record<string, unknown>) {
        const p = profileData(String(args.path ?? ''))
        if (p === undefined) {
          return { kind: 'empty', lines: 0, bytes: 0, verdict: 'cannot read the file', why: 'read failed' }
        }
        options.onProfile?.(p)
        return {
          kind: p.kind,
          lines: p.lines,
          bytes: p.bytes,
          why: p.why,
          verdict: p.verdict,
          duplicate_ratio: p.duplicateRatio,
          ...(p.delimiter === undefined ? {} : { delimiter: p.delimiter }),
          non_text_ratio: p.nonTextRatio,
          longest_line: p.longestLine,
          field_counts: [...p.fieldCounts],
          top_prefixes: [...p.topPrefixes],
        }
      },
    },
  ]
}

export function installDataProfileTools(
  ctx: { tools: { register(tool: ToolDefinition): void } },
  options: { readonly onProfile?: (p: DataProfile) => void } = {},
): void {
  for (const tool of dataProfileTools(options)) ctx.tools.register(tool)
}
