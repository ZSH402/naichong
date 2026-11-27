import fs from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { ClaimStore } from '/root/异构agent/dsh-secops/dist/provenance-tools.js'
import { refuteTools } from '/root/异构agent/dsh-secops/dist/refute-tools.js'
import { oracleTools } from '/root/异构agent/dsh-secops/dist/oracle-tools.js'
import { searchTools } from '/root/异构agent/dsh-secops/dist/search-tools.js'
import { patchTools } from '/root/异构agent/dsh-secops/dist/patch-tools.js'
import { CveStore } from '/root/异构agent/dsh-secops/dist/cve-store.js'
const execFileAsync = promisify(execFile)
const L = (s='') => console.log(s)
const REPO = '/root/异构agent/dsh-secops'

const store = new ClaimStore()
const [refute, oracle, rank, patcher] = [refuteTools(store)[0], oracleTools(store)[0], searchTools(store)[0], patchTools()[0]]

L('════════ 白盒 0day 全链路（六层）════════\n')

// L1 感知
L('【L1 感知】tree-sitter 调用图')
const { stdout: g } = await execFileAsync('python3', ['/root/异构agent/engine/nav/callgraph.py','build',REPO], {maxBuffer: 8e6})
const gs = JSON.parse(g)
L(`  ${gs.files} 文件 · ${gs.functions} 函数 · ${gs.call_edges} 条调用边 · ${gs.unresolved_calls} 条外部调用`)
const { stdout: rc } = await execFileAsync('python3', ['/root/异构agent/engine/nav/callgraph.py','callers',REPO,'refutePath'], {maxBuffer: 8e6})
L(`  refutePath 的调用方: ${JSON.parse(rc).callers.join(', ')}\n`)

// L1 路由簇（引擎 B）
L('【L1 路由簇】同簇守卫覆盖对比')
const { stdout: rt } = await execFileAsync('python3', ['/root/异构agent/engine/nav/callgraph.py','routes',REPO], {maxBuffer: 8e6})
const routes = JSON.parse(rt)
for (const c of routes.clusters.filter(x=>x.routes>1).slice(0,3)) L(`  ${c.prefix.padEnd(16)} ${c.routes} 条 / 有守卫 ${c.guarded} / 可疑 ${c.suspicious.length}`)
L()

// L3 候选
L('【L3 候选】OSV 索引查询 npm:lodash@4.17.20')
const cves = new CveStore({ path: '/tmp/e2e2.jsonl' })
cves.importOsv(JSON.parse(fs.readFileSync('/tmp/osv_merged.json','utf8')))
for (const h of cves.query({product:'lodash',version:'4.17.20',limit:3})) L(`  ${h.cve.id}  ${h.cve.severity.padEnd(9)} fix>=${h.fixAt}`)
L()

// L3 变体
L('【L3 变体】补丁 → 变异查询')
const pv = await patcher.execute({before_text:'function renderName(user) { return formatName(user.name) }', after_text:'function renderName(user) { if (user == null) { return \'\' } return formatName(user.name) }'}, {})
L(`  类型 ${pv.kind} · 汇点 ${pv.signals.slice(0,3).join(',')}\n`)

// 三条断言进入搜索
const h1 = store.assert('POST /api/user/export 未校验租户归属，可越权导出')
const h2 = store.assert('POST /api/internal/impersonate 缺少调用方身份校验')
const h3 = store.assert('GET /probe/token 会回显服务端随机串')
store.attach(h1.id, { ref:'e1', pathKey:'p1', executed:'curl -X POST http://t/api/user/export', executedTrusted:true })

// L2 搜索
L('【L2 搜索】UCB1 排序：下一步测哪条')
const nx = await rank.execute({limit:3}, {})
for (const p of nx.picks) L(`  ${String(p.score).padStart(6)}  ${p.claim.slice(0,44)}  — ${p.reason.slice(0,46)}`)
L()

// L4 反驳（幻觉）
L('【L4 反驳】幻觉端点')
const rbyc = await refute.execute({claim_id:h2.id, repo:REPO}, {})
L(`  ${store.get(h2.id).status.padEnd(11)} ${rbyc.verdict}\n`)

// L5 实证
L('【L5 实证】沙箱内取证')
const run = await oracle.execute({claim_id:h3.id, argv:['sh','-c','echo "GET /probe/token 200 token=CNRY-e2e"'], expect:{type:'canary',token:'CNRY-e2e'}, timeout_sec:20, mem:'128M', note:'first'}, {})
L(`  ${run.outcome} (${run.elapsed_ms}ms) — ${run.reason.slice(0,60)}`)
const run2 = await oracle.execute({claim_id:h3.id, argv:['sh','-c','echo "GET /probe/token second-path token=CNRY-e2e"'], expect:{type:'sanitizer'}, timeout_sec:20, mem:'128M', note:'second'}, {})
L(`  第二路径: ${run2.outcome} — ${run2.reason.slice(0,60)}`)
const run3 = await oracle.execute({claim_id:h3.id, argv:['sh','-c','curl -s http://127.0.0.1:9/probe/token || echo "GET /probe/token unreachable"'], expect:{type:'output-contains',text:'GET /probe/token'}, timeout_sec:20, mem:'128M', note:'second'}, {})
L(`  独立路径2: ${run3.outcome} → 状态 ${store.get(h3.id).status}\n`)

L('════════ 结论 ════════')
for (const c of store.query()) L(`  ${c.status.padEnd(11)} 路径${c.independentPaths}  ${c.claim.slice(0,46)}`)
