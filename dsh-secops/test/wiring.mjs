/**
 * 接线回归：断言「谁把什么传给了谁」，而不是断言函数逻辑。
 *
 * 两次真机故障都是这个形态：
 *   一、claim_id 传到工具层就停了，createQueueAttempt 没拿到 link —— 工具报
 *      settled=true，claim 永远拿不到证据，两边都不报错。
 *   二、schema 加了字段但 render 没加 —— 模型看到 NOT_RETURNED，只能如实说「没返回」。
 *
 * 两次单测全绿。函数级测试覆盖不了接线，因为接线断掉时每个函数都还对。
 *
 * 这里用两种手段：
 *   A. 直接读编译产物，断言那几行关键调用长什么样（防漂移，快，不 flaky）
 *   B. 构造工具定义直接调 execute，用记录型假 dispatcher 看参数是否透传
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { AgentRegistry, DEFAULT_AGENTS } from '../dist/agent-registry.js'
import { DirectionalDispatcher } from '../dist/agent-dispatch.js'
import { agentTools } from '../dist/agent-tools.js'
import { Council, councilTools } from '../dist/council/index.js'
import { ClaimStore } from '../dist/provenance-tools.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const here = path.dirname(fileURLToPath(import.meta.url))
const read = (rel) => fs.readFileSync(path.join(here, '..', rel), 'utf8')

// ── A. 源码接线断言
{
  const index = read('dist/index.js')

  // 第一次踩坑：link 必须在执行层，不在工具层
  const attemptCall = index.slice(index.indexOf('createQueueAttempt('), index.indexOf('createQueueAttempt(') + 400)
  check('createQueueAttempt receives link (the evidence wiring)', attemptCall.includes('link:'), attemptCall.slice(0, 200))

  check('registry is built from DEFAULT_AGENTS', index.includes('new AgentRegistry(DEFAULT_AGENTS)'))
  check('council is given the real claim store', /new Council\(\{[\s\S]{0,400}claims:\s*claimStore/.test(index))
  check('council tools are installed', index.includes('installCouncilTools(ctx, council)'))
  check('agent tools are installed', index.includes('installAgentTools(ctx, dispatcher, registry'))
  check('dispatcher reports whether claims can be linked', index.includes('supportsClaim:'))

  const agentToolsSrc = read('dist/agent-tools.js')
  // 第二次踩坑：schema 加了字段，render 也必须有
  for (const field of ['claim_linked', 'stop_reason', 'shape', 'cost_spent']) {
    check(`dispatch render carries ${field}`, agentToolsSrc.includes(`${field}=`), field)
  }
  // 只查函数体，不含注释：注释里那段历史说明是刻意留的（解释为什么改成 key=value）。
  const renderBody = agentToolsSrc.slice(
    agentToolsSrc.indexOf('function renderDispatch('),
    agentToolsSrc.indexOf('function renderStatus(') > 0 ? agentToolsSrc.indexOf('function renderStatus(') : undefined,
  )
  check('dispatch render never emits natural-language "settled by"', !/['"`]settled by/.test(renderBody), renderBody.slice(0, 200))

  const adaptersSrc = read('dist/council/adapters.js')
  check('cli adapter forwards preferAgentId', adaptersSrc.includes('preferAgentId'))
  check('cli adapter forwards claimId', adaptersSrc.includes('claimId'))
  check('cli adapter always produces a reason', adaptersSrc.includes('reason:'))
}

// ── B. 工具定义层的参数透传
{
  const seen = []
  const registry = new AgentRegistry(DEFAULT_AGENTS)
  const fakeDispatcher = {
    async dispatch(request) {
      seen.push(request)
      return {
        settled: true,
        found: false,
        by: 'stub',
        stopReason: 'settled',
        shape: 'binary',
        costSpent: 1,
        claimLinked: request.claimId !== undefined,
        attempts: [{ agentId: 'stub', direction: request.direction, result: 'completed', fitness: 1, cost: 'cheap', evidenceDir: '/tmp/stub' }],
      }
    },
  }
  const tools = agentTools(fakeDispatcher, registry, {})
  const dispatchTool = tools.find((t) => t.name === 'agent_dispatch')

  await dispatchTool.execute({ direction: 'binary-reverse', target: '/usr/bin/ls', claim_id: 'claim-xyz', second_opinion: true })
  const got = seen[0]
  check('agent_dispatch forwards claim_id to the dispatcher', got?.claimId === 'claim-xyz', got)
  check('agent_dispatch forwards second_opinion', got?.secondOpinion === true, got)
  check('agent_dispatch forwards the direction', got?.direction === 'binary-reverse', got)

  // 给了 claim 但执行层没链上时，必须显式告诉模型
  const noClaimDispatcher = {
    async dispatch() {
      return { settled: true, found: true, stopReason: 'settled', shape: 'file', costSpent: 1, claimLinked: false, attempts: [] }
    },
  }
  const t2 = agentTools(noClaimDispatcher, registry, {}).find((t) => t.name === 'agent_dispatch')
  const out2 = await t2.execute({ direction: 'binary-reverse', target: '/usr/bin/ls', claim_id: 'claim-xyz' })
  check('unlinked claim is reported instead of silently ignored', typeof out2.claim_note === 'string', out2)
}

// ── C. council 工具层透传
{
  const claims = new ClaimStore(undefined, { strictRelevance: false })
  const registry = new AgentRegistry(DEFAULT_AGENTS)
  let captured
  const fakeDispatcher = {
    async dispatch(request) {
      captured = request
      return {
        settled: true,
        found: false,
        by: 'rabin2',
        stopReason: 'settled',
        shape: 'binary',
        costSpent: 1,
        claimLinked: false,
        attempts: [{ agentId: 'rabin2', direction: request.direction, result: 'completed', fitness: 1, cost: 'cheap', evidenceDir: '/tmp/stub' }],
      }
    },
  }
  const dispatcher = new DirectionalDispatcher({
    registry,
    evidenceRoot: '/tmp/secops-wiring-evidence',
    attempt: () => Promise.resolve({ kind: 'completed', found: false }),
  })
  // 用真 dispatcher 只为满足 Council 构造；执行走 fakeDispatcher 记录参数
  const council = new Council({
    registry,
    dispatcher: Object.assign(dispatcher, { dispatch: fakeDispatcher.dispatch }),
    claims,
    paths: { roster: '/tmp/secops-wiring-roster.jsonl', board: '/tmp/secops-wiring-board.jsonl' },
  })
  const tools = councilTools(council)
  check('council exposes exactly three tools', tools.length === 3, tools.map((t) => t.name))

  const names = tools.map((t) => t.name)
  for (const n of ['council_assess', 'council_run', 'council_status']) {
    check(`council tool present: ${n}`, names.includes(n))
  }

  const runTool = tools.find((t) => t.name === 'council_run')
  const ran = await runTool.execute({
    target: '/usr/bin/ls',
    directions: ['binary-reverse'],
    max_tasks: 1,
    manual_hypotheses: [
      { statement: '该二进制缺少栈保护', falsifiable_by: 'checksec 显示 canary=yes 即不成立', direction: 'binary-reverse' },
    ],
  })
  check('council_run reaches the dispatcher', captured !== undefined, captured)
  check('council_run reports a stop-aware summary', typeof ran.executed === 'number', ran)
  check('council_run returns next actions', Array.isArray(ran.next_actions), ran)

  const statusTool = tools.find((t) => t.name === 'council_status')
  const status = await statusTool.execute({})
  check('council_status has no budget section', status.budget === undefined && status.limits !== undefined, Object.keys(status))
}

// ── D. claim 投影必须把归因和来源给到模型
// 加了字段但投影不带，模型就只能盲操作——这是本项目第三次踩同一个坑。
{
  const agentToolsSrc = read('dist/provenance-tools.js')
  // 第三次同类疏漏了：schema 加了字段但参数列表没加，模型会以为工具没有这个能力。
  const evTool = read('dist/provenance-tools.js')
  check('claim_evidence exposes role', /role:\s*\{[^}]*proof/.test(evTool), 'role missing from claim_evidence parameters')
  check('claim projection carries blame', /blame:\s*claim\.blame/.test(agentToolsSrc), 'no blame in project()')
  check('claim projection carries the producing tool', agentToolsSrc.includes('e.source.argv[0]'), 'no source in project()')
  check('claim_refute accepts blame_agent', agentToolsSrc.includes('blame_agent'))
  check('council_status exposes precision', read('dist/council/index.js').includes('false_positive_rate'))
  // 第四次同类疏漏的预防：control 角色必须同时出现在 schema 描述、参数说明和投影里。
  check('claim_evidence documents role=control', /control/.test(evTool) && /calibrat/.test(evTool), 'control role undocumented')
  check('claim projection carries verification strength', /verification:\s*verificationOf/.test(agentToolsSrc), 'no verification in project()')
  check('detector_check tool exists', read('dist/control-tools.js').includes("name: 'detector_check'"), 'detector_check missing')
  check('control gate refuses unrecorded refs', read('dist/control-check.js').includes('controlGateOf'), 'no gate')
  check('calibrated state exists', read('dist/provenance.js').includes('calibrated'), 'no calibrated state')
}



// ── E. MCP 绑定只能有一份，且判据不能把「不知道」写成「没问题」
{
  const bind = read('dist/mcp-bindings.js')
  check('mcp bindings live in one module', /export function defaultMcpBindings/.test(bind), 'no shared bindings module')
  check('production entry uses shared bindings', /defaultMcpBindings\(\)/.test(read('dist/index.js')), 'index.js still inlines bindings')
  const mod = await import('../dist/mcp-bindings.js')
  const b = mod.defaultMcpBindings()
  for (const id of ['cyberstrike-nmap', 'cyberstrike-ghidra', 'cyberstrike-sqlmap', 'cyberstrike-dirsearch']) {
    check(`binding present: ${id}`, b.has(id), [...b.keys()])
  }
  // ghidra 的参数名是 `binary`（schema required），写成 target 会直接报缺参。
  const ghidraArgs = b.get('cyberstrike-ghidra').args({ target: '/bin/ls' })
  check('ghidra binding uses the binary param', ghidraArgs.binary === '/bin/ls' && ghidraArgs.target === undefined, ghidraArgs)
  const nmapArgs = b.get('cyberstrike-nmap').args({ target: 'http://10.0.0.5:8080/x' })
  check('nmap binding strips the URL', nmapArgs.target === '10.0.0.5', nmapArgs)

  const sqlmap = b.get('cyberstrike-sqlmap').verdict
  const v = (text) => sqlmap({ text, isError: false, raw: {} })
  check('sqlmap: confirmed block is a finding', v('Parameter: id (GET)\n  Type: boolean-based blind')?.found === true, v('Parameter: id (GET)\n  Type: x'))
  check('sqlmap: explicit not-injectable is clean', v('all tested parameters do not appear to be injectable')?.class === 'clean')
  check('sqlmap: bare Parameter line is unknown, not negative', v('Parameter: id (GET)') === undefined, v('Parameter: id (GET)'))

  const dir = b.get('cyberstrike-dirsearch').verdict
  check(
    'dirsearch: discovered paths are not findings',
    dir({ text: '  [10:00:00] 200 -  12B  - /index.html', isError: false, raw: {} })?.found === false,
  )
  check('dirsearch: no hits is unknown', dir({ text: 'nothing', isError: false, raw: {} }) === undefined)
}

// ── F. 奖惩：中性值两处必须一致，且 status 真的把它暴露出来
{
  const reg = read('dist/agent-registry.js')
  const credit = read('dist/council/credit.js')
  // registry 里那份 CREDIT_NEUTRAL 是排序用的，credit.ts 里那份是算分用的。
  // 两边漂了不会报错，只会让「中性牌 priority 不变」这条悄悄失效。
  const inReg = /CREDIT_NEUTRAL = ([0-9.]+)/.exec(reg)?.[1]
  const inCredit = /CREDIT_NEUTRAL = ([0-9.]+)/.exec(credit)?.[1]
  check('CREDIT_NEUTRAL is identical in both modules', inReg !== undefined && inReg === inCredit, { registry: inReg, credit: inCredit })
  check('council status exposes credit', /credit: this\.credit\?\.all\(\)/.test(read('dist/council/index.js')), 'status() has no credit')
  check('status schema declares credit', /credit:\s*\{[^}]*type: 'array'/.test(read('dist/council/index.js')), 'STATUS_SCHEMA missing credit')
  check('council refreshes credit before planning', /credit\?\.refresh/.test(read('dist/council/index.js')), 'no refresh')
  check('dispatcher accepts creditOf', /creditOf/.test(read('dist/agent-dispatch.js')), 'dispatcher ignores credit')
  check('config defaults credit on', /enabled: input\.council\?\.credit\?\.enabled \?\? true/.test(read('dist/config.js')), 'credit not on by default')
  check('status exposes per-shape credit', /creditByShape/.test(read('dist/council/index.js')), 'no shape view')
  check('shape travels with the claim', /setShape/.test(read('dist/provenance-tools.js')) && /shape/.test(read('dist/queue-tools.js')), 'shape not recorded on claims')
  check('creditOf receives the shape', /creditOf\?\.\(candidate\.id, shape\)/.test(read('dist/agent-registry.js')), 'shape not passed to creditOf')
  check('decay has a default half-life', /DEFAULT_HALF_LIFE_MS/.test(read('dist/council/credit.js')), 'no decay default')
  check('relevance channel exists', /tallyRelevance/.test(read('dist/council/credit.js')), 'no relevance channel')
  check('board refetches claims instead of caching a snapshot', /fetchClaims/.test(read('dist/council/credit.js')), 'stale snapshot risk')
  check('entry wires the fetch function', /fetchClaims: \(\) => claimStore\.query\(\)/.test(read('dist/index.js')), 'index does not wire fetchClaims')
  check('stall can charge time credit', /credit\b/.test(read('dist/stall-guard.js')) && /debit/.test(read('dist/stall-guard.js')), 'stall does not debit')
  check('dispatch budget scales to the slowest candidate', /budgetFor/.test(read('dist/agent-tools.js')), 'fixed overall timeout')
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
