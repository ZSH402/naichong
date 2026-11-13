/**
 * HITL（Human-in-the-Loop）：高风险操作的人工/独立审核层。
 *
 * 设计取自 CyberStrikeAI 的 HITL 实践，三条核心原则：
 *
 *   1. **硬底线是代码，不是提示词**。删除、格式化、写系统文件这类操作
 *      由 guard 直接拒绝，任何 reviewer（包括 audit agent）都无法放行。
 *   2. **allowlist 只免审批，不授予权限**。白名单里的工具仍然要过范围闸和预算闸，
 *      只是不再弹审批。审批与授权是两件事，不能混。
 *   3. **review-edit 只能收窄，不能扩大**。审核者可以缩小目标范围后再放行，
 *      但不能借审批之机扩大攻击面。
 *
 * 落地在 DSH 的两个不同层：
 *   - `ctx.tools.guard()`：同步、单调拒绝 —— 放硬底线
 *   - `tools/pre-execute` waterfall：异步、可返回 ask —— 放审批
 */

/** 风险等级。 */
export type RiskLevel = 'read' | 'write' | 'destructive' | 'c2'

export interface HitlPolicy {
  readonly allowlist: readonly string[]
  readonly requireApproval: readonly RiskLevel[]
  readonly hardFloor?: (toolName: string, args: unknown) => string | undefined
}

/** 只读类工具名前缀/全名。 */
const READ_PATTERNS = [
  /^read/, /^ls$/, /^cat$/, /^head$/, /^tail$/, /^glob/, /^grep/, /^find$/,
  /^get_/, /^list_/, /^search_/, /^query_/, /^stat$/, /^wc$/,
]

/** 写类。 */
const WRITE_PATTERNS = [/^write/, /^edit/, /^create/, /^mkdir/, /^touch/, /^upload/, /^patch/, /^apply_patch/]

/** 破坏性。 */
const DESTRUCTIVE_PATTERNS = [
  /^rm$/, /^rmdir$/, /^delete/, /^drop/, /^truncate/, /^format/, /^mkfs/,
  /^dd$/, /^shred/, /^wipe/, /^clear_data/, /^purge/,
]

/** C2 / 反弹 shell / webshell。 */
const C2_PATTERNS = [/^webshell/, /^c2_/, /^reverse_shell/, /^bind_shell/, /^beacon/, /^implant/]

function matchesAny(name: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((p) => p.test(name))
}

/**
 * 从工具名与参数推断风险等级。
 *
 * 命令行工具（bash/pwsh/shell）要看命令内容：`rm -rf` 和 `ls` 都是 bash，
 * 但风险差着一个数量级。
 */
export function classifyRisk(toolName: string, args: unknown): RiskLevel {
  const name = toolName.toLowerCase()

  // 命令执行类：解析命令本身
  if (name === 'bash' || name === 'pwsh' || name === 'shell' || name === 'exec') {
    const command = commandText(args).toLowerCase()
    if (/\b(mkfs|dd\s+if=|shred|rm\s+-rf\s+\/|:\(\)\s*\{)/.test(command)) return 'destructive'
    if (/\b(rm|rmdir|drop\s+table|truncate|shutdown|reboot|kill\s+-9)\b/.test(command)) return 'destructive'
    if (/\b(nc|ncat|socat)\b.*\s-(e|c)\s/.test(command) || /bash\s+-i\s+>&/.test(command)) return 'c2'
    if (/\b(curl|wget|scp|rsync)\b.*(\s-[oO]\s|--upload-file)/.test(command)) return 'write'
    return 'read'
  }

  if (matchesAny(name, C2_PATTERNS)) return 'c2'
  if (matchesAny(name, DESTRUCTIVE_PATTERNS)) return 'destructive'
  if (matchesAny(name, WRITE_PATTERNS)) return 'write'
  if (matchesAny(name, READ_PATTERNS)) return 'read'

  // 未知工具默认按写处理：宁可多问一次，也不要放过未知的破坏路径
  return 'write'
}

function commandText(args: unknown): string {
  if (typeof args !== 'object' || args === null) return ''
  const rec = args as Record<string, unknown>
  for (const key of ['command', 'cmd', 'script', 'code']) {
    const v = rec[key]
    if (typeof v === 'string') return v
  }
  return ''
}

/**
 * 默认硬底线：这些无论谁审都不会放行。
 *
 * 只拦**确定会有灾难性后果**的操作，不做泛化的"危险命令"匹配 ——
 * 后者会误杀正常的渗透动作（本来就是拿 shell、删测试数据）。
 */
export function defaultHardFloor(toolName: string, args: unknown): string | undefined {
  const name = toolName.toLowerCase()
  const cmd = commandText(args).toLowerCase()

  // 系统级破坏
  if (/\bmkfs(\.\w+)?\s+\/dev\//.test(cmd)) return 'refusing to format a block device'
  if (/\bdd\b[^|;]*\bof=\/dev\/[sh]d/.test(cmd)) return 'refusing to write a raw disk image'
  if (isRecursiveForceRoot(cmd)) return 'refusing rm -rf /'
  if (/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(cmd)) return 'refusing to fork-bomb the host'

  // 系统账户与凭据
  if (/(>>?|\btee\b[^|;]*)\s*\/etc\/(passwd|shadow|sudoers)\b/.test(cmd)) return 'refusing to write system account files'

  // 引导与内核
  if (/\b(grub-install|update-grub|modprobe\s+-r|insmod|rmmod)\b/.test(cmd)) return 'refusing to modify boot or kernel modules'

  // 文件级：写系统目录
  if (name.startsWith('write') || name === 'edit' || name === 'apply_patch') {
    const path = filePathOf(args)
    if (path !== undefined && /^\/(etc|boot|sys|proc)\//.test(path)) {
      return `refusing to write under system path ${path}`
    }
  }

  return undefined
}

/** 判断是否 `rm` 递归强制删除根目录（-r 与 -f 可能分处两个 flag）。 */
function isRecursiveForceRoot(cmd: string): boolean {
  const m = /\brm\s+([^;&|]*)/.exec(cmd)
  if (m === null) return false
  const args = m[1]!.trim()
  if (!/(^|\s)\/(\s|$)/.test(args)) return false
  const recursive = /(^|\s)-[a-zA-Z]*r/i.test(args) || /--recursive/.test(args)
  const force = /(^|\s)-[a-zA-Z]*f/i.test(args) || /--force/.test(args)
  return recursive && force
}

function filePathOf(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const rec = args as Record<string, unknown>
  for (const key of ['path', 'file_path', 'filePath', 'target']) {
    const v = rec[key]
    if (typeof v === 'string' && v.length > 0) return v
  }
  return undefined
}

/** 是否需要审批。 */
export function needsApproval(risk: RiskLevel, toolName: string, policy: HitlPolicy): boolean {
  if (policy.allowlist.includes(toolName)) return false
  return policy.requireApproval.includes(risk)
}

/** 默认策略：只读免审，写/破坏/C2 要审批。 */
export function defaultPolicy(): HitlPolicy {
  return {
    allowlist: [],
    requireApproval: ['write', 'destructive', 'c2'],
    hardFloor: defaultHardFloor,
  }
}
