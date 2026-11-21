/**
 * 证据相关性校验。
 *
 * 要解决的问题：独立路径数只度量「有几条不同来路的证据」，不度量
 * 「证据是否关于这条断言」。端到端验证里模型拿 `node -e "console.log(7)"`
 * 当「PUT /api/user 越权」的证据，系统照单全收。
 *
 * 判据：**证据的实际执行内容必须触及断言里的可核对锚点。**
 * 锚点从断言文本确定性提取（路径 / 方法 / 参数名 / 状态码 / 主机），
 * 不依赖模型自述。这样 `console.log(7)` 冒充不了 `/api/user` 的证据。
 *
 * 为什么不用 LLM 判定：那是用模型判断模型的证据，循环论证。
 * 为什么不做纯文本相似度：`/api/user` 与 `/api/users` 相似度很高但语义不同；
 * 锚点是精确 token 匹配，可复现、可解释。
 */

/** 断言里的一个可核对锚点。 */
export interface Anchor {
  readonly kind: 'path' | 'method' | 'param' | 'status' | 'host'
  /** 规范化后的值（method 大写、host 小写、其余原样）。 */
  readonly value: string
}

/**
 * 参数名的判定：不做通用标识符提取（噪声太大），只认两类——
 * `name=` 形式的显式赋值，以及安全语义上高频的字段名。
 */
const PARAM_ASSIGN = /\b([a-zA-Z_][a-zA-Z0-9_]{1,29})\s*[=:]/g
const PARAM_WELL_KNOWN = new Set([
  'id', 'uid', 'user', 'userid', 'userId', 'account', 'owner', 'tenant', 'org',
  'role', 'roles', 'admin', 'isadmin', 'scope', 'permission', 'group',
  'token', 'authcode', 'code', 'session', 'cookie', 'signature',
  'amount', 'price', 'quantity', 'count', 'balance', 'total',
  'email', 'phone', 'password', 'secret',
])

const HTTP_METHOD = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/gi
/** 路径：以 / 开头、至少两段，允许 {id} 占位符。 */
const URL_PATH = /\/[A-Za-z0-9_\-.{}]+(?:\/[A-Za-z0-9_\-.{}]+)*/g
const STATUS_CODE = /\b([1-5]\d{2})\b/g
const HOSTNAME = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|dev|local|example|test|internal))\b/gi

/** 过滤明显的噪声路径（时间戳、单段斜杠等）。 */
function isNoisePath(p: string): boolean {
  if (p.length < 4) return true
  // 纯数字/日期形态
  if (/^\/\d+$/.test(p)) return true
  // 太长的不像路径，更像正则或句子里的斜杠
  if (p.length > 120) return true
  return false
}

/**
 * 从一段文本里提取锚点。
 *
 * 确定性、无副作用、可单测。同一文本多次调用返回相同结果。
 */
export function extractAnchors(text: string): Anchor[] {
  const out: Anchor[] = []
  const seen = new Set<string>()
  const push = (kind: Anchor['kind'], value: string): void => {
    const key = `${kind}:${value}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ kind, value })
  }

  for (const m of text.matchAll(URL_PATH)) {
    const p = m[0].replace(/[.,;:)]+$/, '')
    if (!isNoisePath(p)) push('path', p)
  }
  for (const m of text.matchAll(HTTP_METHOD)) push('method', m[1]!.toUpperCase())
  for (const m of text.matchAll(STATUS_CODE)) push('status', m[1]!)
  for (const m of text.matchAll(HOSTNAME)) push('host', m[1]!.toLowerCase())
  for (const m of text.matchAll(PARAM_ASSIGN)) {
    const name = m[1]!
    const lower = name.toLowerCase()
    if (PARAM_WELL_KNOWN.has(lower) || PARAM_WELL_KNOWN.has(name)) push('param', lower)
  }
  for (const word of text.split(/[^A-Za-z0-9_]+/)) {
    const lower = word.toLowerCase()
    if (PARAM_WELL_KNOWN.has(lower)) push('param', lower)
  }
  return out
}

export interface RelevanceVerdict {
  readonly ok: boolean
  /** strong = 实际执行内容覆盖锚点；weak = 仅声明覆盖；none = 未覆盖。 */
  readonly strength: 'strong' | 'weak' | 'none'
  readonly anchors: readonly Anchor[]
  readonly matched: readonly Anchor[]
  readonly reason?: string
}

export interface RelevanceInput {
  /** 断言原文。 */
  readonly claim: string
  /** 证据的实际执行内容（命令 / argv / 请求行的拼接）。 */
  /**
   * 实际执行的命令/请求。
   *
   * ⚠️ 单独看它**不能**当证据：这是模型可以随便填的字符串。
   * 只有 `executedTrusted === true`（上游确实拿到了真实的 argv）时才计入 strong。
   * 而 `executedTrusted` 只能由系统设置——模型没有途径传入它。
   */
  readonly executed?: string
  /**
   * `executed` 是否来自系统记录的真实 argv（例如队列任务的 task.argv）。
   * 模型无法提供这一位，所以自述永远拿不到 strong。
   */
  readonly executedTrusted?: boolean
  /**
   * 执行产物摘要（stdout/stderr 片段）。**必须由系统读取，不能由模型传入**。
   *
   * 这条是端到端验证后加的：早期版本用调用方自述的 `observed` 做第二判据，
   * 模型只需在 observes 里复述断言原文就能绕过校验——自述不能当证据。
   */
  readonly artifact?: string
  /** 证据引用，用于诊断。 */
  readonly ref?: string
  /**
   * `artifact` 是否来自系统读取（而不是模型传入）。
   *
   * 为什么需要这一位：产物单独看无法自证——`echo "PUT /api/user 200"` 也能造出
   * 含锚点的输出。但如果产物是**系统从模型指定路径读出来的文件**，它就至少
   * 是一份真实存在的存档，人可以照着核查。这正是漏洞赏金平台接受截图/视频的
   * 理由：不要求可重放，要求**内容可核查**。
   *
   * 所以两种产物的可信度不同：
   *   - 系统读取的文件 → attested（可推进确认，但标注未重放）
   *   - 模型传入的文本 → weak（不计入，等同自述）
   */
  readonly artifactTrusted?: boolean
}

/**
 * 判定一条证据是否与断言相关。
 *
 * 规则：
 *   1. 断言必须至少有一个锚点，否则无法核对 —— 除非 `strict: false`，此时降级为 weak。
 *   2. **实际执行内容**（argv / 请求行）覆盖任一锚点 → strong。
 *   3. **执行产物**覆盖锚点但执行内容不含 → weak（产物可能由 echo 伪造，故不算强）。
 *   4. 两者都不覆盖 → none，拒绝。
 *
 * 只有 strong 计入 `verifiedPaths`（升级 confirmed 的口径）。见 provenance.ts。
 */
export function checkEvidenceRelevance(input: RelevanceInput, options: { strict?: boolean } = {}): RelevanceVerdict {
  const strict = options.strict ?? true
  const anchors = extractAnchors(input.claim)
  const executed = input.executed ?? ''
  const artifact = input.artifact ?? ''

  if (anchors.length === 0) {
    return {
      ok: !strict,
      strength: 'weak',
      anchors: [],
      matched: [],
      reason: strict
        ? 'claim has no checkable anchors (path/method/param/host/status); rewrite it as a specific statement'
        : 'claim has no checkable anchors; relevance cannot be verified',
    }
  }

  const executedText = executed.toLowerCase()
  const artifactText = artifact.toLowerCase()

  const inExecuted = anchors.filter((a) => executedText.includes(a.value.toLowerCase()))
  if (inExecuted.length > 0) {
    // 只有系统记录的真实 argv 才算强证据。模型自述的 executed 降级为 weak ——
    // 它最多说明"我认为我执行过这个"，不能作为确认依据。
    const trusted = input.executedTrusted === true
    return {
      ok: true,
      strength: trusted ? 'strong' : 'weak',
      anchors,
      matched: inExecuted,
      ...(trusted ? {} : {
        reason: 'executed content was supplied as text, not from a system-recorded argv; treated as assertion',
      }),
    }
  }

  const inArtifact = anchors.filter((a) => artifactText.includes(a.value.toLowerCase()))
  if (inArtifact.length > 0) {
    // 系统读取的真实产物文件 → attested，可以推进确认。
    // 模型传入的文本 → weak，不计入（等同自述）。
    const trusted = input.artifactTrusted === true
    return {
      ok: true,
      strength: trusted ? 'strong' : 'weak',
      anchors,
      matched: inArtifact,
      reason: trusted
        ? 'anchors matched in evidence file read by the system (attested: not replayed)'
        : 'anchors appear only in caller-supplied text, which cannot be distinguished from narration',
    }
  }

  return {
    ok: false,
    strength: 'none',
    anchors,
    matched: [],
    reason:
      `evidence does not touch any anchor of the claim ` +
      `(expected one of: ${anchors.map((a) => `${a.kind}=${a.value}`).join(', ')})`,
  }
}

/** 把一条证据标记为「已核对相关性」时需要的最小信息。 */
export interface RelevanceRecord {
  readonly strength: 'strong' | 'weak'
  readonly matched: readonly Anchor[]
}
