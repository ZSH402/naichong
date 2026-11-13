/**
 * 资产库 + 接线自检验收。
 *
 * 两件事：扫描结果要能落成结构（否则下一步推导只能靠记忆），
 * 以及接线问题要在启动时被喊出来（否则要等真跑才发现）。
 */
import { AssetStore, extractAssets } from '../dist/asset-store.js'
import { checkWiring, checkCandidate } from '../dist/wiring-check.js'
import { DEFAULT_AGENTS } from '../dist/agent-registry.js'
import { verificationOf } from '../dist/provenance.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

// ── 1. 从 nmap 输出提资产
{
  const ex = extractAssets('internal-ad', '22/tcp ssh, 445/tcp netbios-ssn, 5432/tcp postgresql', '10.0.0.5')
  check('host extracted', ex.some((a) => a.kind === 'host' && a.id === '10.0.0.5'), ex)
  check('three services extracted', ex.filter((a) => a.kind === 'service').length === 3, ex)
  check('services hang under the host', ex.filter((a) => a.kind === 'service').every((a) => a.parent === '10.0.0.5'), ex)
  check('port recorded', ex.some((a) => a.kind === 'service' && a.attrs?.port === '445'))
}

// ── 2. 从 URL 提 endpoint
{
  const ex = extractAssets('web-pentest', '0 matches', 'http://10.0.0.5:8080/api/user')
  check('url yields host', ex.some((a) => a.kind === 'host' && a.id === '10.0.0.5:8080'), ex)
  check('url yields endpoint', ex.some((a) => a.kind === 'endpoint' && a.id.includes('/api/user')), ex)
  check('endpoint hangs under host', ex.find((a) => a.kind === 'endpoint')?.parent === '10.0.0.5:8080', ex)
}

// ── 3. 从 enum4linux 提共享
{
  const ex = extractAssets('internal-ad', 'null session accepted; shares: pub,IPC$', '10.0.0.5')
  const shares = ex.filter((a) => a.kind === 'share')
  check('shares extracted', shares.length === 2, ex)
  check('share keeps its name', shares.some((a) => a.attrs?.name === 'pub'))
}

// ── 4. 认不出格式时宁可不产出
{
  const ex = extractAssets('unknown-direction', 'some free text', 'x')
  check('unknown direction yields nothing', ex.length === 0, ex)
}

// ── 5. 同一方向多次检查取最强结论
{
  const s = new AssetStore()
  s.record({ id: 'h:445', kind: 'service', seen: { 'internal-ad': 'finding' } })
  s.markChecked('h:445', 'internal-ad', 'clean')
  check('a later clean does not erase an earlier finding', s.get('h:445')?.seen['internal-ad'] === 'finding', s.get('h:445'))
}

// ── 6. 查询：未检查的资产是真空白
{
  const s = new AssetStore()
  s.record({ id: 'h', kind: 'host' })
  s.record({ id: 'h:445', kind: 'service', parent: 'h', seen: { 'internal-ad': 'exposure' } })
  check('unchecked lists only untouched', s.list({ unchecked: true }).map((a) => a.id).join(',') === 'h', s.list({ unchecked: true }))
  check('children of a host', s.children('h').map((a) => a.id).join(',') === 'h:445')
  check('summary counts kinds', s.summary().byKind['service'] === 1, s.summary())
}

// ── 7. 持久化
{
  const fs = await import('node:fs'), os = await import('node:os'), path = await import('node:path')
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'asset-')), 'a.jsonl')
  const a = new AssetStore(p)
  a.record({ id: 'x:80', kind: 'service', parent: 'x', seen: { 'web-pentest': 'finding' } })
  const b = new AssetStore(p)
  check('assets survive reload', b.get('x:80')?.seen['web-pentest'] === 'finding', b.get('x:80'))
}

// ── 8. 接线自检：真实 roster 必须干净
{
  const r = checkWiring(DEFAULT_AGENTS)
  check('no wiring errors in the real roster', r.errors === 0, r.issues.filter((i) => i.level === 'error'))
  check('report counts every candidate', r.checked === DEFAULT_AGENTS.length)
}

// ── 9. 接线自检：能抓到真实的接线缺陷
{
  const bad = checkCandidate({ id: 'broken', direction: 'web-pentest', kind: 'cli', capability: 'x', command: ['x'] })
  check('cli without invocation is an error', bad.some((i) => i.code === 'missing-invocation' && i.level === 'error'), bad)

  const mcpBad = checkCandidate({ id: 'm', direction: 'web-pentest', kind: 'mcp', capability: 'x' })
  check('mcp without probeCommand is an error', mcpBad.some((i) => i.code === 'missing-probe-command'), mcpBad)

  const ok = checkCandidate({ id: 'fine', direction: 'web-pentest', kind: 'mcp', capability: 'x', probeCommand: '/bin/true', invocation: () => ['x'] })
  check('complete mcp candidate has no errors', ok.filter((i) => i.level === 'error').length === 0, ok)
}

// ── 10. 验证强度三档
{
  const base = { claim: 'x', status: 'confirmed', independentPaths: 2, createdAt: 1, updatedAt: 1, blame: undefined }
  const ev = (role, replayed) => ({
    ref: 'r', pathKey: 'k', addedAt: 1,
    ...(role === undefined ? {} : { role }),
    ...(replayed ? { replay: { verified: true, at: 1, exitCode: 0, digest: 'd', matchKind: 'strict' } } : {}),
  })
  check('no replay means none', verificationOf({ ...base, evidence: [ev('proof', false)] }) === 'none')
  check('replay alone means reproducible', verificationOf({ ...base, evidence: [ev('proof', true)] }) === 'reproducible')
  check('replay plus baseline means cross-checked',
    verificationOf({ ...base, evidence: [ev('proof', true), ev('baseline', false)] }) === 'cross-checked')
  check('a non-strict replay does not count',
    verificationOf({ ...base, evidence: [{ ...ev('proof', false), replay: { verified: true, at: 1, exitCode: 0, digest: 'd', matchKind: 'structural' } }] }) === 'none')
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
