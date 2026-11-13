/**
 * SecOps 面板 —— host 半边。
 *
 * 只做一件事：把 claim 存储以只读 JSON 暴露给同源的前端。
 *
 * 为什么需要这一层：claim 的持久化落在 `$DSH_HOME/secops/claims.jsonl`，
 * 而浏览器拿不到文件系统。DSH 自带的 session projection 看着像现成的路，
 * 但它在这套组合下拿不到数据——`recordClaim` 会抛
 * `Receiver must be an instance of class Session`，因为 app-boot 的自定义
 * ESM loader 把同一个 `dsh-session` 加载成了两份模块记录，brand check 跨实例失败。
 * 那是宿主侧的问题，不在这个面板能改的范围内。
 *
 * 所以这里不做投影、不写事件，只读那个本来就已经是唯一真相的文件。
 *
 * 安全：路由仅注册在 DSH 自己的 webServer 上（绑定 127.0.0.1，继承宿主的鉴权），
 * 只接受 GET，不做写入，也不回显任务文本之外的任何东西。
 */

import fs from 'node:fs'
import path from 'node:path'

/** 前端与这里必须用同一个常量。 */
const ROUTE = '/secops-ledger'
const COVERAGE_ROUTE = '/secops-coverage'
const CREDENTIALS_ROUTE = '/secops-credentials'

/** 单次返回的 claim 上限。面板是给人看的，不是导数据的通道。 */
const MAX_CLAIMS = 500

function ledgerPath() {
  const home = process.env.DSH_HOME ?? ''
  if (home === '') return undefined
  return path.join(home, 'secops', 'claims.jsonl')
}

/**
 * 读全量快照。
 *
 * 文件是 append-only 的，同一 claim 的后续快照覆盖先前（last-wins），
 * 与 ClaimStore 的持久化语义一致——两边对「哪个是最新」的判断必须一样，
 * 否则面板会显示一条已经被推翻的旧结论。
 */
function readClaims() {
  const file = ledgerPath()
  if (file === undefined) return { claims: [], note: 'DSH_HOME 未设置，找不到 claim 存储' }
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    const code = error?.code
    if (code === 'ENOENT') return { claims: [], note: 'claim 存储还不存在（还没有跑过一轮）' }
    return { claims: [], note: `读取失败：${String(code ?? error)}` }
  }

  const byId = new Map()
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '') continue
    try {
      const claim = JSON.parse(trimmed)
      if (claim !== null && typeof claim === 'object' && typeof claim.id === 'string') byId.set(claim.id, claim)
    } catch {
      // 半行（写入中途崩溃）直接跳过 —— append-only 的价值就在这里。
    }
  }

  const all = [...byId.values()]
  const sorted = all.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
  return { claims: sorted.slice(0, MAX_CLAIMS), total: all.length }
}

/** `${cwd}/.dsh-secops` —— CoverageLedger / AssetStore 的落点，跟着工作目录走。 */
function stateDir() {
  return path.join(process.cwd(), '.dsh-secops')
}

/**
 * 读 JSONL 账本并按 key 去重（last-wins）。
 *
 * coverage 和 assets 都是 append-only 快照流，同一条记录的后续快照覆盖先前——
 * 与它们各自的 store 语义一致。文件不存在返回 undefined，让调用方能区分
 * 「没有记录」和「读失败」。
 */
function readJsonl(file, keyOf) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined
    throw error
  }
  const by = new Map()
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '') continue
    try {
      const row = JSON.parse(trimmed)
      const key = keyOf(row)
      if (key !== undefined) by.set(key, row)
    } catch {
      // 半行跳过
    }
  }
  return [...by.values()]
}

function readCoverage() {
  const rows = readJsonl(path.join(stateDir(), 'coverage.jsonl'), (r) =>
    typeof r?.asset === 'string' && typeof r?.check === 'string' ? `${r.asset}::${r.check}` : undefined,
  )
  if (rows === undefined) return { rows: [], note: '当前工作目录下还没有覆盖记录' }
  return { rows: rows.sort((a, b) => (b.at ?? 0) - (a.at ?? 0)), total: rows.length }
}

function readAssets() {
  const rows = readJsonl(path.join(stateDir(), 'assets.jsonl'), (r) => (typeof r?.id === 'string' ? r.id : undefined))
  if (rows === undefined) return { rows: [], note: '当前工作目录下还没有资产记录' }
  return { rows: rows.sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0)), total: rows.length }
}

function jsonResponse(req, res, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  res.end(req.method === 'HEAD' ? undefined : body)
}

/** `$DSH_HOME/credentials.json` —— 与 dsh-secops 的 readAgentCredentials 同一个文件。 */
function credentialsPath() {
  const home = process.env.DSH_HOME ?? ''
  return home === '' ? undefined : path.join(home, 'credentials.json')
}

function readCredentialsFile() {
  const file = credentialsPath()
  if (file === undefined) return { agents: {} }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
    const agents = parsed?.agents
    return { agents: agents !== null && typeof agents === 'object' ? agents : {} }
  } catch {
    return { agents: {} }
  }
}

/**
 * 只回显「配没配」和后四位。
 *
 * 面板是给人看状态的，不是凭据查看器——回显全文等于把 key 复制到一个
 * 会被截图、被浏览器插件读到、可能留在会话记录里的地方。
 */
function maskValue(value) {
  if (typeof value !== 'string' || value === '') return ''
  return value.length <= 4 ? '****' : `…${value.slice(-4)}`
}

function describeCredentials() {
  const { agents } = readCredentialsFile()
  const out = {}
  for (const [agentId, entry] of Object.entries(agents)) {
    if (entry === null || typeof entry !== 'object') continue
    const keys = Object.keys(entry).filter((k) => typeof entry[k] === 'string' && entry[k] !== '')
    out[agentId] = {
      configured: keys.length > 0,
      keys: keys.map((k) => ({ name: k, hint: maskValue(entry[k]) })),
    }
  }
  return out
}

/** 写一个凭据字段。只接受本次会话同源发起的请求。 */
function writeCredential(agentId, key, value) {
  const file = credentialsPath()
  if (file === undefined) return { ok: false, reason: 'DSH_HOME 未设置' }
  if (typeof agentId !== 'string' || !/^[a-z0-9-]{1,40}$/i.test(agentId)) return { ok: false, reason: 'agentId 不合法' }
  if (typeof key !== 'string' || !/^[A-Z0-9_]{1,60}$/.test(key)) return { ok: false, reason: 'key 名不合法（大写字母数字下划线）' }
  if (typeof value !== 'string' || value === '') return { ok: false, reason: 'value 为空' }

  const { agents } = readCredentialsFile()
  const next = { ...agents }
  const entry = next[agentId] !== null && typeof next[agentId] === 'object' ? { ...next[agentId] } : {}
  if (value === '__CLEAR__') delete entry[key]
  else entry[key] = value
  next[agentId] = entry

  const body = `${JSON.stringify({ agents: next }, null, 2)}\n`
  const tmp = `${file}.tmp`
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(tmp, body, { mode: 0o600 })
  fs.renameSync(tmp, file)
  try {
    fs.chmodSync(file, 0o600)
  } catch {
    /* 已有文件的权限位改不动就保持原样 */
  }
  return { ok: true }
}

/** 只认同源：面板永远从宿主自己的 origin 发起写请求。 */
function sameOrigin(req) {
  const origin = req.headers?.origin
  const host = req.headers?.host
  if (typeof origin !== 'string' || typeof host !== 'string') return false
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = ''
    let tooLarge = false
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 64 * 1024) {
        tooLarge = true
        req.destroy()
      }
    })
    req.on('end', () => {
      if (tooLarge) return resolve(undefined)
      try {
        resolve(JSON.parse(raw))
      } catch {
        resolve(undefined)
      }
    })
    req.on('error', () => resolve(undefined))
  })
}

function apply(ctx) {
  ctx.inject(['webServer'], (webCtx) => {
    webCtx.effect(
      () =>
        webCtx.webServer.register({
          kind: 'exact',
          path: ROUTE,
          handler: async (req, res) => {
            if (req.method !== 'GET' && req.method !== 'HEAD') {
              res.writeHead(405, { allow: 'GET, HEAD' })
              res.end()
              return
            }
            let payload
            try {
              payload = { ...readClaims(), ...readTimeCredit(ctx), readAt: Date.now() }
            } catch (error) {
              payload = { claims: [], note: `内部错误：${String(error)}` }
            }
            jsonResponse(req, res, payload)
          },
        }),
      'client-ui-secops: ledger route',
    )

    // 覆盖账本单开一条：它跟着 cwd 走，和 claim 的文件位置不同（那边跟 DSH_HOME）。
    webCtx.effect(
      () =>
        webCtx.webServer.register({
          kind: 'exact',
          path: COVERAGE_ROUTE,
          handler: async (req, res) => {
            if (req.method !== 'GET' && req.method !== 'HEAD') {
              res.writeHead(405, { allow: 'GET, HEAD' })
              res.end()
              return
            }
            let payload
            try {
              payload = { ...readCoverage(), assets: readAssets(), readAt: Date.now() }
            } catch (error) {
              payload = { rows: [], assets: { rows: [] }, note: `内部错误：${String(error)}` }
            }
            jsonResponse(req, res, payload)
          },
        }),
      'client-ui-secops: coverage route',
    )

    // 凭据：GET 看状态（脱敏），POST 写入。写入必须同源，且带 content-type 检查——
    // 跨站表单发不出 application/json，等于多一道免费的 CSRF 防线。
    webCtx.effect(
      () =>
        webCtx.webServer.register({
          kind: 'exact',
          path: CREDENTIALS_ROUTE,
          handler: async (req, res) => {
            if (req.method === 'GET' || req.method === 'HEAD') {
              jsonResponse(req, res, { agents: describeCredentials(), readAt: Date.now() })
              return
            }
            if (req.method !== 'POST') {
              res.writeHead(405, { allow: 'GET, HEAD, POST' })
              res.end()
              return
            }
            if (!sameOrigin(req) || !String(req.headers?.['content-type'] ?? '').includes('application/json')) {
              res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
              res.end('forbidden')
              return
            }
            const body = await readBody(req)
            const result = writeCredential(body?.agentId, body?.key, body?.value)
            if (!result.ok) {
              res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' })
              res.end(JSON.stringify({ ok: false, reason: result.reason }))
              return
            }
            jsonResponse(req, res, { ok: true, agents: describeCredentials() })
          },
        }),
      'client-ui-secops: credentials route',
    )
  })
}

/**
 * 时间信用快照。
 *
 * 它原本是纯内存对象，没有观测入口；dsh-secops 现在把它 provide 成服务。
 * 用 ctx.get 而不是 inject：这个 UI 包不该因为后端没提供它就不工作——
 * 拿不到就如实显示「未接入」，而不是让整个面板停在加载中。
 */
function readTimeCredit(ctx) {
  let credit
  try {
    credit = ctx.get('secopsTimeCredit')
  } catch {
    return { timeCredit: undefined }
  }
  if (credit === undefined || typeof credit.view !== 'function') return { timeCredit: undefined }
  try {
    const v = credit.view()
    return {
      timeCredit: {
        started: v.started,
        baseMs: v.base,
        grantedMs: v.granted,
        debitedMs: v.debited,
        totalMs: v.total,
        spentMs: v.spent,
        remainingMs: v.remaining,
        expired: v.expired,
        grants: Array.isArray(v.grants)
          ? v.grants.slice(-20).map((g) => ({ kind: g.kind, detail: g.detail, at: g.at, amount: g.amount }))
          : [],
      },
    }
  } catch (error) {
    return { timeCredit: undefined, timeCreditNote: String(error) }
  }
}

export { apply, ROUTE }
