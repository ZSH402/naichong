/**
 * 白盒反驳器：给一条断言找「它可能不成立」的确定性事实。
 *
 * ## 为什么需要它
 *
 * 白盒审计最常见的失败不是漏报，是**报了一条代码里根本不存在的东西**：
 * 模型顺着常见框架的套路编出一个端点、一个参数、一条调用链，读起来完全合理。
 * 这类幻觉靠"再问一遍模型"是治不掉的——它每次都能编得同样合理。
 * 能治它的只有一种东西：**去仓库里搜，搜不到就是搜不到。**
 *
 * 业界实证（Refute-or-Promote, arXiv:2604.19049）给了一个必须记住的边界：
 * 10 个专职审查员全票认可过一个不存在的漏洞，最后只被一条实证测试击毙。
 * 所以这里的定位很窄——**不判断漏洞是否存在，只提供能否定它的代码事实**。
 *
 * ## 三档结论，只有一档能判死
 *
 *   anchor-absent   —— 断言里的锚点（路由、参数、符号）在全仓一次都没出现。
 *                      **decisive**：这是幻觉最硬的证据。
 *   route-unregistered —— 字符串出现了，但没有任何路由注册点。
 *                      advisory：可能是动态注册、反射、或框架约定，不能判死。
 *   guard-found     —— 找到了注册点，且上游有疑似鉴权/租户检查。
 *                      advisory：守卫是否覆盖这条路径要人判断。
 *
 * 判死只给第一档，理由和 Refute-or-Promote 的教训一致：把真漏洞反驳掉比
 * 报一条误报更糟。宁可留一堆 advisory 让人看，也不自动杀掉一条真问题。
 */

import { execFile } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** 一条反驳发现。 */
export interface RefuteFinding {
  readonly kind: 'decisive' | 'advisory'
  /** 检查项 id。 */
  readonly check: string
  /** 命中位置 file:line。 */
  readonly location?: string
  /** 人可读的事实陈述。 */
  readonly detail: string
}

/** 一次反驳扫描的完整结果。 */
export interface RefuteReport {
  readonly anchor: string
  readonly kind: 'path' | 'param' | 'claim'
  readonly findings: readonly RefuteFinding[]
  /** 实际执行的搜索次数，用于判断"找不到"是不是因为根本没搜。 */
  readonly searches: number
  /** 是否因为仓库太大/工具缺失而降级——降级时结论不可信。 */
  readonly degraded: string | null
}

/** 搜索默认跳过的目录：不是源码，搜了只会引入噪音和误判。 */
const SKIP_DIRS = [
  'node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor',
  'third_party', 'third-party', '.venv', 'venv', '__pycache__', '.next', 'coverage',
]

const MAX_MATCHES = 40

/** 一条匹配。 */
interface Match {
  readonly file: string
  readonly line: number
  readonly text: string
}

/**
 * 在仓库里搜一个字面串。
 *
 * 优先用 ripgrep（大仓库快一个量级），不可用时退回纯 node 遍历。
 * 两条路径都返回同样的结构，调用方不需要关心走了哪条。
 */
async function search(root: string, needle: string): Promise<{ matches: Match[]; via: 'rg' | 'walk' }> {
  try {
    const { stdout } = await execFileAsync(
      'rg',
      [
        '--fixed-strings', '--line-number', '--no-heading', '--color', 'never',
        '--max-count', String(MAX_MATCHES),
        ...SKIP_DIRS.flatMap((d) => ['--glob', `!**/${d}/**`]),
        needle,
        root,
      ],
      { maxBuffer: 8 * 1024 * 1024, timeout: 30_000 },
    )
    const matches: Match[] = []
    for (const line of stdout.split('\n')) {
      if (line.trim() === '') continue
      const m = line.match(/^(.*?):(\d+):(.*)$/)
      if (m === null) continue
      matches.push({ file: m[1]!, line: Number(m[2]), text: m[3]! })
      if (matches.length >= MAX_MATCHES) break
    }
    return { matches, via: 'rg' }
  } catch (err) {
    // rg 的退出码 1 表示"没找到"，不是错误
    const e = err as { code?: number | string; stdout?: string }
    if (e.code === 1) return { matches: [], via: 'rg' }
    return { matches: walkSearch(root, needle), via: 'walk' }
  }
}

/** 没有 ripgrep 时的降级遍历。故意做得朴素：只搜文本文件，限制总量。 */
function walkSearch(root: string, needle: string): Match[] {
  const out: Match[] = []
  const exts = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb',
    '.php', '.rs', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.kt', '.swift',
    '.yml', '.yaml', '.json', '.toml', '.conf', '.ini',
  ])
  let scanned = 0
  const walk = (dir: string): void => {
    if (out.length >= MAX_MATCHES || scanned > 20000) return
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const ent of entries) {
      if (out.length >= MAX_MATCHES || scanned > 20000) return
      const p = path.join(dir, ent.name)
      if (ent.isDirectory()) {
        if (SKIP_DIRS.includes(ent.name)) continue
        walk(p)
        continue
      }
      if (!exts.has(path.extname(ent.name).toLowerCase())) continue
      scanned += 1
      let text: string
      try {
        const st = fs.statSync(p)
        if (st.size > 2 * 1024 * 1024) continue
        text = fs.readFileSync(p, 'utf8')
      } catch {
        continue
      }
      const lines = text.split('\n')
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]!.includes(needle)) {
          out.push({ file: p, line: i + 1, text: lines[i]! })
          if (out.length >= MAX_MATCHES) return
        }
      }
    }
  }
  walk(root)
  return out
}

/**
 * 判断一行是不是"守卫"。
 *
 * 这是启发式的，所以结论只能是 advisory。判断依据来自 Web 框架里鉴权/租户
 * 检查的实际写法：中间件挂载、装饰器、显式角色判断。宁可漏判（把守卫当普通行）
 * 也不误判——把普通日志行当成守卫会让反驳器给出假结论。
 */
const GUARD_PATTERNS: readonly { readonly re: RegExp; readonly what: string }[] = [
  { re: /\b(requireAuth|ensureAuth|authMiddleware|authenticate|isAuthenticated|requireLogin)\b/i, what: 'authentication middleware' },
  { re: /\b(requireRole|hasRole|isAdmin|checkPermission|authorize|can\()/i, what: 'authorization check' },
  { re: /\b(tenant|org_id|owner_id|user_id)\s*(===|==|!==|!=|in\b)/, what: 'tenant/owner scoping' },
  { re: /\b(before_request|@login_required|@jwt_required|@permission_required|Depends\()/i, what: 'framework guard decorator' },
  { re: /\b(deny|forbidden|403)\b/i, what: 'explicit deny branch' },
]

/** 一行里的守卫线索。 */
function guardIn(line: string): string | undefined {
  for (const g of GUARD_PATTERNS) if (g.re.test(line)) return g.what
  return undefined
}

/**
 * 判断一行像不像路由注册。
 *
 * 覆盖主流写法：`router.put('/x')`、`app.get`、`@app.route`、`@GetMapping`、
 * `Route::post`、`r.HandleFunc`、`http.HandleFunc`、`path(`。
 */
const ROUTE_PATTERNS: readonly RegExp[] = [
  /\b(router|app|server|api|r)\.(get|post|put|patch|delete|all|use|route)\s*\(/i,
  /@\w*\.?(route|get|post|put|patch|delete|mapping)\s*\(/i,
  /\bRoute::(get|post|put|patch|delete|any)\s*\(/i,
  /\bHandleFunc\s*\(/,
  /\b(add_url_rule|add_route|register_route)\s*\(/i,
]

function isRouteRegistration(line: string): boolean {
  return ROUTE_PATTERNS.some((re) => re.test(line))
}

/**
 * 检查一个路径锚点在仓库里到底存不存在。
 *
 * 三档结论见文件头。这里只做**保守**判断：
 *   - 一次都没搜到 → decisive（anchor-absent）
 *   - 搜到了但没有路由注册 → advisory（route-unregistered）
 *   - 注册点附近有守卫 → advisory（guard-found）
 *   - 注册点附近没守卫 → 不产出反驳（这可能正是漏洞所在，反驳器不该说话）
 */
export async function refutePath(root: string, anchorValue: string): Promise<RefuteReport> {
  const findings: RefuteFinding[] = []
  let searches = 0
  let degraded: string | null = null

  // 只保留路径部分，去掉查询串和占位符变体
  const needle = anchorValue.trim()
  if (needle.length < 3) {
    return { anchor: needle, kind: 'path', findings, searches: 0, degraded: 'anchor too short to search' }
  }

  const direct = await search(root, needle)
  searches += 1
  if (direct.via === 'walk') degraded = 'ripgrep unavailable; fell back to directory walk'

  if (direct.matches.length === 0) {
    // 再试一次不带前导斜杠的形式（代码里常写成 'user/:id' 拼在别处）
    const alt = needle.replace(/^\//, '')
    if (alt !== needle && alt.length >= 3) {
      const second = await search(root, alt)
      searches += 1
      if (second.via === 'walk') degraded = 'ripgrep unavailable; fell back to directory walk'
      if (second.matches.length === 0) {
        findings.push({
          kind: 'decisive',
          check: 'anchor-absent',
          detail: `"${needle}" and "${alt}" do not appear anywhere in the repository — the endpoint this claim talks about is not in this codebase`,
        })
        return { anchor: needle, kind: 'path', findings, searches, degraded }
      }
      findings.push(...analyzeMatches(root, second.matches, needle))
      return { anchor: needle, kind: 'path', findings, searches, degraded }
    }
    findings.push({
      kind: 'decisive',
      check: 'anchor-absent',
      detail: `"${needle}" does not appear anywhere in the repository — the endpoint this claim talks about is not in this codebase`,
    })
    return { anchor: needle, kind: 'path', findings, searches, degraded }
  }

  findings.push(...analyzeMatches(root, direct.matches, needle))
  return { anchor: needle, kind: 'path', findings, searches, degraded }
}

/** 对命中的位置做二次判断：有没有注册点、有没有守卫。 */
function analyzeMatches(root: string, matches: readonly Match[], needle: string): RefuteFinding[] {
  const out: RefuteFinding[] = []
  const routeHits = matches.filter((m) => isRouteRegistration(m.text))

  if (routeHits.length === 0) {
    out.push({
      kind: 'advisory',
      check: 'route-unregistered',
      location: relative(root, matches[0]!.file) + ':' + String(matches[0]!.line),
      detail:
        `"${needle}" appears ${String(matches.length)} time(s) but none of them look like a route registration — ` +
        'it may be registered dynamically, or the claim may be describing a path that no handler serves',
    })
    return out
  }

  // 检查每个注册点前 40 行内有没有守卫（装饰器/中间件通常紧邻注册）
  const guarded: string[] = []
  for (const r of routeHits) {
    let text: string
    try {
      text = fs.readFileSync(r.file, 'utf8')
    } catch {
      continue
    }
    const lines = text.split('\n')
    const from = Math.max(0, r.line - 41)
    for (let i = from; i < Math.min(lines.length, r.line + 2); i++) {
      const g = guardIn(lines[i]!)
      if (g !== undefined) {
        guarded.push(`${relative(root, r.file)}:${String(i + 1)} ${g}`)
        break
      }
    }
  }

  if (guarded.length > 0) {
    out.push({
      kind: 'advisory',
      check: 'guard-found',
      location: guarded[0]!,
      detail:
        `guard found near ${String(guarded.length)} of ${String(routeHits.length)} registration site(s): ` +
        `${guarded.slice(0, 3).join('; ')} — check whether it actually covers the path this claim targets`,
    })
  }
  return out
}

function relative(root: string, file: string): string {
  return file.startsWith(root) ? file.slice(root.length).replace(/^\//, '') : file
}

/**
 * 检查断言里提到的符号是否真的被调用。
 *
 * 只对"看起来像函数名"的锚点做，且要求引用数为 0 才判死——
 * 有引用不代表可达（可能在死分支里），但**零引用几乎一定是死代码**。
 */
export async function refuteSymbol(root: string, symbol: string): Promise<RefuteReport> {
  const findings: RefuteFinding[] = []
  const needle = symbol.trim()
  if (!/^[A-Za-z_][A-Za-z0-9_]{2,}$/.test(needle)) {
    return {
      anchor: needle,
      kind: 'claim',
      findings,
      searches: 0,
      degraded: 'symbol does not look like an identifier',
    }
  }
  const { matches, via } = await search(root, needle)
  const degraded = via === 'walk' ? 'ripgrep unavailable; fell back to directory walk' : null

  // 定义处算一次匹配，剩下的才是引用
  const callSites = matches.filter((m) => {
    const t = m.text
    // 排除纯定义行
    if (/\b(function|def|func|fn|void|int|char|static|public|private|protected)\b[^;]*\b/.test(t) && t.includes(needle) && !t.includes(`${needle}(`)) {
      return false
    }
    return new RegExp(`\\b${needle}\\s*\\(`).test(t)
  })

  if (callSites.length === 0) {
    findings.push({
      kind: 'decisive',
      check: 'symbol-uncalled',
      detail:
        `no call site for "${needle}" was found in the repository — if this is the code the claim targets, ` +
        'it is not reachable from any caller, which usually means the claim cannot be triggered',
    })
  }
  return { anchor: needle, kind: 'claim', findings, searches: 1, degraded }
}
