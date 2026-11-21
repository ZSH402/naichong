/**
 * dsh-secops — 安全测试编排的领域层插件。
 *
 * 三项职责，各自落在 DSH 已有的原生接缝上：
 *   1. 范围闸：ctx.tools.guard() —— 单调拒绝，与注册顺序无关，不可被其它插件 force-allow
 *   2. 预算闸：ctx.tools.guard() —— 同上，计数与墙钟
 *   3. 决策阶段：agent/pre-step waterfall —— reject 即让 turn 以 blocked 结束
 *
 * 设计约束（来自源码核实，见 docs/决策层设计.md）：
 *   - guard 是同步的，不能做 DNS 解析或网络探测。范围检查是**第一道过滤器**，
 *     真正的强制必须在网络层（SandboxProvider 的 --unshare-net + netns/代理）。
 *   - pre-step 的顺序不保证（cordis 的 prepend 是 unshift，后注册者更靠前），
 *     所以安全拦截一律走 guard，不走 pre-step。
 */
import path from 'node:path';
import { installBudgetGuard, installScopeGuard, installToolDenyGuard } from "./guards.js";
import { installDecisionStage } from "./decision.js";
import { DecisionPolicy } from "./decision-policy.js";
import { decisionTools } from "./decision-tools.js";
import { EgressProxy } from "./egress.js";
import { ModelFallback } from "./model-fallback.js";
import { classifyRisk, defaultHardFloor, needsApproval } from "./hitl.js";
import { ClaimStore, installProvenanceTools } from "./provenance-tools.js";
import { registerProvenanceProjection } from "./provenance.js";
import { QueueRunner } from "./queue-runner.js";
import { createEvidenceArchiver, installQueueTools } from "./queue-tools.js";
import { SessionManager } from "./session-manager.js";
import { sessionTools } from "./session-tools.js";
import { installSessionGuard } from "./session-guard.js";
import { installStallGuard } from "./stall-guard.js";
import { installShortcutGuard } from "./shortcut-guard.js";
import { installGuidanceGuard, GUIDANCE_FILENAME } from "./guidance.js";
import { installAnswerTools } from "./answer-tools.js";
import { installDataProfileTools } from "./data-profile.js";
import { CoverageLedger, installCoverageTools } from "./coverage.js";
import { AssetStore, assetTools } from "./asset-store.js";
import { checkWiring, reportWiring } from "./wiring-check.js";
import { ArtexClient, createArtexAdapter } from "./council/artex-adapter.js";
import { createMcpAdapter, closeAllMcpClients } from "./council/mcp-adapter.js";
import { defaultMcpBindings } from "./mcp-bindings.js";
import { TimeCredit } from "./time-credit.js";
import { creditForProgress, installTimeCreditGuard, installTimeCreditTools } from "./time-credit-guard.js";
import { AgentRegistry, DEFAULT_AGENTS, probeAgents } from "./agent-registry.js";
import { ControlLedger, controlGateOf } from "./control-check.js";
import { CreditBoard } from "./council/credit.js";
import { installControlTools } from "./control-tools.js";
import { DirectionalDispatcher } from "./agent-dispatch.js";
import { createQueueAttempt, installAgentTools } from "./agent-tools.js";
import { Council, installCouncilTools } from "./council/index.js";
import { resolveConfig } from "./config.js";
export const name = 'secops';
/**
 * 硬依赖 tools：guard 必须注册到工具注册表上。
 * 没有 tools 时插件保持 PENDING，不会带着半套策略跑起来。
 */
export const inject = ['tools'];
export async function apply(ctx, config) {
    const resolved = resolveConfig(config);
    installToolDenyGuard(ctx, resolved.deniedTools);
    // 停滞检测：连续做同一件事的变体时插一句话，要求把假设写下来并直接攻击可证伪点。
    // 外部指导：人在会话运行期间递一句话进来，下一轮生效。
    // 没有它，想推 agent 一把只能 kill 重开，上下文全丢。
    installGuidanceGuard(ctx, {
        filePath: `${process.cwd()}/${GUIDANCE_FILENAME}`,
        logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
    });
    // 捷径拦截：搜答案超过两次就拒绝。危害不是浪费时间，是它可能碰巧成功。
    const shortcut = installShortcutGuard(ctx, {
        logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
    });
    ctx.effect(() => () => {
        const s = shortcut.stats();
        if (s.hits > 0)
            ctx.logger.info(`secops/shortcut: 共 ${String(s.hits)} 次搜答案，拒绝 ${String(s.blocks)} 次`);
    });
    // 时间信用要最先建：stall 检测会往它上面扣时间，claimStore 拿它做续期回调。
    // 之前它建在 stall 之后，于是「原地打转」只能提醒、不能扣——奖惩只做了一半。
    const timeCredit = resolved.timeCredit.enabled
        ? new TimeCredit({
            baseMs: resolved.timeCredit.baseMs,
            grantMs: resolved.timeCredit.grantMs,
            maxMs: resolved.timeCredit.maxMs,
            grantCooldownMs: resolved.timeCredit.grantCooldownMs,
            warnAtMs: resolved.timeCredit.warnAtMs,
            debitMs: resolved.timeCredit.debitMs,
            maxDebitMs: resolved.timeCredit.maxDebitMs,
            debitCooldownMs: resolved.timeCredit.debitCooldownMs,
        })
        : undefined;
    const stall = installStallGuard(ctx, {
        logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
        ...(timeCredit === undefined ? {} : { credit: timeCredit }),
    });
    ctx.effect(() => () => {
        const s = stall.stats();
        if (s.nudges > 0)
            ctx.logger.info(`secops/stall: ${String(s.nudges)} 次提醒 / ${String(s.calls)} 次调用`);
    });
    installScopeGuard(ctx, resolved);
    installBudgetGuard(ctx, resolved);
    // HITL：硬底线走 guard（同步、单调拒绝，任何 reviewer 无法覆盖）；
    // 审批走 pre-execute waterfall（可返回 ask，由 ctx.approval 分派）。
    const hitl = resolved.hitl;
    if (hitl.enabled) {
        const policy = {
            allowlist: hitl.allowlist,
            requireApproval: hitl.requireApproval,
            hardFloor: defaultHardFloor,
        };
        // 硬底线：在 guard 层直接拒绝
        ctx.tools.guard((exec) => {
            const reason = policy.hardFloor?.(exec.name, exec.arguments);
            return reason === undefined ? undefined : `[secops/hitl] ${reason}`;
        });
        // 审批：pre-execute 返回 ask
        ctx.on('tools/pre-execute', async (exec, next) => {
            const decision = await next();
            if (decision.kind !== 'allow')
                return decision;
            const risk = classifyRisk(exec.name, exec.arguments);
            if (!needsApproval(risk, exec.name, policy))
                return decision;
            return {
                kind: 'ask',
                reason: `[secops/hitl] ${risk}-risk operation: ${exec.name}`,
            };
        });
        ctx.logger.info(`secops: HITL armed (approval for ${hitl.requireApproval.join('/')}, ` +
            `${hitl.allowlist.length} allowlisted tool(s))`);
    }
    // 模型 fallback：唯一在 DSH 里没有现成实现的能力。
    // 落点是 agent/request-error（决定切不切）+ agent/request（把下次请求指向备用路由）。
    if (resolved.fallback.routes.length > 1) {
        const fallback = new ModelFallback({
            routes: resolved.fallback.routes,
            maxSwitches: resolved.fallback.maxSwitches,
        });
        ctx.on('agent/request-error', async (payload, next) => {
            if (fallback.onRequestError(payload.agent.id, payload.failure)) {
                ctx.logger.info(`secops/fallback: ${payload.agent.id} switching provider after ${payload.failure.code}`);
                return { kind: 'retry' };
            }
            return next();
        });
        ctx.on('agent/request', async (payload, next) => {
            const config = await next();
            const route = fallback.routeFor(payload.agent.id, config);
            if (route === undefined)
                return config;
            return { ...config, provider: route.provider, model: route.model };
        });
        ctx.logger.info(`secops: model fallback armed (${resolved.fallback.routes.map((r) => `${r.provider}/${r.model}`).join(' → ')})`);
    }
    // 决策阶段要先注册 projection 再挂监听，所以是异步的。
    // policy 实例在审计工具与 pre-step 之间共享 —— 审计读的是同一条决策流。
    const decisionPolicy = new DecisionPolicy();
    await installDecisionStage(ctx, resolved, { policy: decisionPolicy });
    for (const tool of decisionTools(decisionPolicy))
        ctx.tools.register(tool);
    if (timeCredit !== undefined) {
        // 把时间信用暴露成一个服务，给只读的 UI 面板读余额与流水。
        // 它原本是纯内存对象，除了工具调用方没有别的观测入口——
        // 「还剩多少时间」在会话里是可见的，在面板上却看不见，说不过去。
        // 用 provide 而不是新增工具：这不是新能力，只是把已有状态放到可读的位置。
        ctx.provide('secopsTimeCredit', timeCredit);
        installTimeCreditGuard(ctx, {
            credit: timeCredit,
            logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
        });
        installTimeCreditTools(ctx, timeCredit);
        // 量清数据结构算一次实质进展：这一步常常决定后面几小时走不走偏。
        // 不靠模型自述——工具真的跑出结果才计价。
        installDataProfileTools(ctx, {
            onProfile: (p) => {
                creditForProgress(timeCredit, { kind: 'structure', claimId: `profile:${p.path}`, detail: `${p.kind} ${String(p.lines)} lines` }, { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) });
            },
        });
        ctx.logger.info(`secops: time credit armed (base=${Math.round(resolved.timeCredit.baseMs / 60000)}m, ` +
            `+${Math.round(resolved.timeCredit.grantMs / 60000)}m per progress, cap=${Math.round(resolved.timeCredit.maxMs / 60000)}m)`);
    }
    // 检测器校准账本。provenance 的 control 闸门和 detector_check 工具共用它：
    // 前者问「这个工具的校准记录可信吗」，后者负责产生记录。
    const controlLedger = new ControlLedger();
    // 断言/证据归属：默认启用。projection 可选（无 sessionProjections 时退化为纯内存）。
    let claimStore;
    if (resolved.provenance.enabled) {
        const store = new ClaimStore(undefined, {
            strictRelevance: resolved.provenance.strict,
            // 没有账本就没有校准，role=control 一律不收。方向是保守的：
            // 拒绝一条无法核对的校准，比接受它然后把断言虚报到 calibrated 便宜得多。
            controlGate: controlGateOf(controlLedger),
            ...(resolved.provenance.store === undefined ? {} : { storePath: resolved.provenance.store }),
            // 进展事件直接换算成续期。判定在 ClaimStore 里做，这里只负责记账。
            ...(timeCredit === undefined
                ? {}
                : {
                    onProgress: (event) => creditForProgress(timeCredit, event, {
                        info: (m) => ctx.logger.info(m),
                        warn: (m) => ctx.logger.warn(m),
                    }),
                }),
        });
        claimStore = store;
        const projections = ctx.get('sessionProjections');
        if (projections !== undefined) {
            try {
                await registerProvenanceProjection(projections);
            }
            catch (error) {
                ctx.logger.warn(`secops: provenance projection unavailable: ${String(error)}`);
            }
        }
        installProvenanceTools(ctx, store);
        // 答案必须有 confirmed 的 claim 撑着，否则只能按推测报告。
        installAnswerTools(ctx, store);
        ctx.logger.info(`secops: provenance tools armed (claim_assert / claim_evidence / claim_verify / claim_refute / claim_query, ` +
            `store=${resolved.provenance.store ?? 'memory-only'})`);
    }
    // 网络出口：可选。启用后队列任务被关进 netns，只有代理是出口。
    let egressSocket;
    if (resolved.egress.enabled) {
        if (resolved.allowedHosts.length === 0) {
            ctx.logger.warn('secops: egress enabled but allowedHosts is empty — refusing to arm an allow-nothing proxy');
        }
        else {
            const proxy = new EgressProxy({
                allowedHosts: resolved.allowedHosts,
                socketPath: resolved.egress.socketPath,
                onDecision: (d) => ctx.logger.info(`secops/egress: ${d.allowed ? 'ALLOW' : 'DENY'} ${d.host}:${d.port}`),
            });
            await proxy.start();
            ctx.effect(() => () => void proxy.stop());
            egressSocket = resolved.egress.socketPath;
            ctx.logger.info(`secops: egress proxy armed at ${egressSocket} (${resolved.allowedHosts.length} host(s))`);
        }
    }
    // 跨进程队列：可选。启用后暴露 worker_submit / worker_status，
    // 并随插件卸载关闭（ctx.effect 保证有序释放）。
    let agentRunner;
    let archiver;
    if (resolved.queue.enabled) {
        archiver = claimStore === undefined ? undefined : createEvidenceArchiver(claimStore);
        const localArchiver = archiver;
        const runner = new QueueRunner({
            queueFile: resolved.queue.file,
            evidenceRoot: resolved.queue.evidenceRoot,
            concurrency: resolved.queue.concurrency,
            defaultTimeoutMs: resolved.queue.timeoutMs,
            requeueInterrupted: resolved.queue.requeueInterrupted,
            ...(egressSocket === undefined ? {} : { netns: { proxySocket: egressSocket } }),
            // 证据自动归档：任务成功结束且声明了 claim_id 时，产物自动成为该 claim 的一条证据。
            ...(localArchiver === undefined
                ? {}
                : {
                    onFinish: (task) => {
                        localArchiver.onFinish(task);
                        const outcome = localArchiver.outcomeOf(task.id);
                        if (outcome !== undefined && !outcome.archived) {
                            ctx.logger.warn(`secops: evidence for ${task.id} rejected — ${outcome.reason}`);
                        }
                    },
                }),
            logger: {
                info: (m) => ctx.logger.info(m),
                warn: (m) => ctx.logger.warn(m),
            },
        });
        const { recovered } = runner.start();
        agentRunner = runner;
        ctx.effect(() => () => runner.close());
        installQueueTools(ctx, runner, {
            ...(archiver?.options ?? {}),
            ...(archiver === undefined ? {} : { outcomeOf: archiver.outcomeOf }),
        });
        ctx.logger.info(`secops: queue armed at ${resolved.queue.file} (concurrency=${resolved.queue.concurrency}, ` +
            `recovered=${recovered.length})`);
    }
    // ── 交互式会话（IAT）──
    //
    // 让 agent 对长驻程序（gdb / nc / REPL）逐步发命令读响应，而不是每次起新进程。
    // EnIGMA（arXiv 2409.16165）在 350 道 CTF 题上验证：交互式工具是最大的单点改进。
    // 会话必须在插件卸载时全部回收——否则 gdb 和被调试程序会变成孤儿进程组。
    {
        const sessionLogDir = path.join(process.cwd(), '.dsh-secops', 'sessions');
        const sessions = new SessionManager({
            maxSessions: 4,
            logDir: sessionLogDir,
        });
        ctx.effect(() => () => {
            const alive = sessions.list().filter((x) => x.alive).length;
            if (alive > 0) {
                ctx.logger.info(`secops/session: 卸载时仍存活 ${String(alive)} 个会话，强制回收`);
            }
            void sessions.closeAll();
        });
        for (const tool of sessionTools(sessions, { logDir: sessionLogDir }))
            ctx.tools.register(tool);
        // 护栏：裸跑 gdb 会阻塞到超时，提示改用交互会话（只提醒不拒绝，见 session-guard.ts）
        const sessionGuard = installSessionGuard(ctx, { logger: ctx.logger });
        ctx.effect(() => () => {
            const st = sessionGuard.stats();
            if (st.nudges > 0) {
                ctx.logger.info(`secops/session: ${String(st.nudges)} 次阻塞式 gdb 提示 / ${String(st.calls)} 次调用`);
            }
        });
        ctx.logger.info(`secops: interactive sessions armed (max=4, logs=${sessionLogDir})`);
    }
    // 方向级调度：同一方向多个 agent，失败自动换下一个。
    // 复用队列的执行器——不为它再造一套证据落盘，否则同一次尝试会有两份互不相认的日志。
    if (!resolved.agentDispatch.enabled) {
        ctx.logger.info('secops: agent dispatch disabled');
    }
    else if (!resolved.queue.enabled) {
        ctx.logger.warn('secops: agent dispatch requested but queue is disabled — dispatch needs the queue evidence pipeline; skipping');
    }
    else if (!agentRunner) {
        ctx.logger.warn('secops: agent dispatch requested but no queue runner is available');
    }
    else {
        const baseDirForState = process.cwd();
        // 覆盖账本：随 agentDispatch 一起启用。它回答「什么还没测」，和 claim 的「测出了什么」并列。
        const coverage = new CoverageLedger(`${baseDirForState}/.dsh-secops/coverage.jsonl`);
        installCoverageTools(ctx, coverage);
        // 资产库：把每次扫描的结果落成可查询的结构，而不是散在证据文件里。
        const assets = new AssetStore(`${baseDirForState}/.dsh-secops/assets.jsonl`);
        for (const tool of assetTools(assets))
            ctx.tools.register(tool);
        // 启动时先把接线问题喊出来，别等第一次派活才发现。
        reportWiring(checkWiring(DEFAULT_AGENTS), {
            info: (m) => ctx.logger.info(m),
            warn: (m) => ctx.logger.warn(m),
        });
        ctx.logger.info(`secops: asset store armed (${String(assets.summary().total)} asset(s) recovered)`);
        ctx.logger.info(`secops: coverage ledger armed (${String(coverage.size)} stamp(s) recovered)`);
        const registry = new AgentRegistry(DEFAULT_AGENTS);
        const probe = probeAgents(registry);
        // 奖惩账本：dispatcher 通过它排序候选，council 每轮刷新它。
        // 关闭时给 undefined，排序退回纯 priority——行为可预测，且不会静默半开。
        const creditBoard = resolved.council.credit.enabled && claimStore !== undefined
            ? new CreditBoard({
                exploreWeight: resolved.council.credit.exploreWeight,
                halfLifeMs: resolved.council.credit.halfLifeMs,
                // 挂版本号 + 取数函数：claim 一有写入，下一次查分就自动重算。
                // 不然「奖惩」要等下一轮 council.run 才生效，而一轮里可能已经
                // 用同一张错牌跑了三次。取数用函数而不是快照，否则重算的还是旧数组。
                versionOf: () => claimStore.version,
                fetchClaims: () => claimStore.query(),
            })
            : undefined;
        const dispatcher = new DirectionalDispatcher({
            registry,
            evidenceRoot: resolved.queue.evidenceRoot,
            // 只有真的把 archiver.link 交给执行层，claim 才会拿到证据。
            supportsClaim: archiver !== undefined,
            policy: {
                maxAttempts: resolved.agentDispatch.maxAttempts,
                deadlineMs: resolved.agentDispatch.overallTimeoutMs,
                costBudget: resolved.agentDispatch.costBudget,
                stopOnInconclusive: resolved.agentDispatch.stopOnInconclusive,
                faultCircuit: resolved.agentDispatch.faultCircuit,
            },
            // 排序只看信誉为 0..1 的那个值；没记录时回调返回 undefined，registry 按中性处理。
            ...(creditBoard === undefined ? {} : { creditOf: (id, shape) => creditBoard.scoreOf(id, shape).value }),
            // link 必须给到执行层：它是在 submit 之前建立 task→claim 关联的唯一时机。
            // 之前把 link 传给 installAgentTools 是错的层级——那里只构造工具描述，
            // 拿不到每次尝试的 taskId，结果是工具报告成功而证据永远为空。
            attempt: createQueueAttempt(agentRunner, {
                cwd: process.cwd(),
                ...(archiver === undefined ? {} : { link: archiver.options.link }),
                logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
            }),
            logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
        });
        installControlTools(ctx, registry, controlLedger);
        installAgentTools(ctx, dispatcher, registry, {
            cwd: process.cwd(),
            overallTimeoutMs: resolved.agentDispatch.overallTimeoutMs,
            logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
        });
        // 三公：把分析/调度/风控分成三份职责，全部落在确定性代码上。
        // 它们复用同一套 dispatcher——不为同一件事造第二个执行路径。
        if (resolved.council.enabled && claimStore !== undefined) {
            const council = new Council({
                registry,
                ...(creditBoard === undefined ? {} : { credit: creditBoard }),
                dispatcher,
                claims: claimStore,
                paths: {
                    roster: `${baseDirForState}/.dsh-secops/roster.jsonl`,
                    board: `${baseDirForState}/.dsh-secops/board.jsonl`,
                },
                coverage,
                assets,
                // CyberStrikeAI 的 MCP server：81 个工具里按候选挑。没有它时 mcp kind 不注册，
                // 那些候选会被 plan 跳过而不是派出去失败。
                ...(resolved.mcp.enabled
                    ? {
                        mcpAdapter: createMcpAdapter({
                            spec: { command: resolved.mcp.command, cwd: resolved.mcp.cwd, timeoutMs: resolved.mcp.timeoutMs },
                            bindings: defaultMcpBindings(),
                            logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
                        }),
                    }
                    : {}),
                // ARTEX 作为 agent kind 的执行体。没有它时 agent kind 是空壳（永远 refused）。
                ...(resolved.artex.enabled
                    ? {
                        agentAdapter: createArtexAdapter(new ArtexClient({
                            baseUrl: resolved.artex.baseUrl,
                            password: resolved.artex.password,
                            logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
                        }), { logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) } }),
                    }
                    : {}),
                censorPolicy: {
                    rateWindowMs: resolved.council.rateWindowMs,
                    rateMaxPerWindow: resolved.council.rateMaxPerWindow,
                    breakerThreshold: resolved.council.breakerThreshold,
                    breakerCooldownMs: resolved.council.breakerCooldownMs,
                    allowedHosts: resolved.council.allowedHosts,
                },
                logger: { info: (m) => ctx.logger.info(m), warn: (m) => ctx.logger.warn(m) },
            });
            ctx.effect(() => () => closeAllMcpClients());
            installCouncilTools(ctx, council);
            ctx.logger.info(`secops: council armed (丞相=分析 / 太尉=调度 / 御史大夫=授权+限流+超时+熔断; ` +
                `scope=${resolved.council.allowedHosts.length === 0 ? 'unrestricted' : `${resolved.council.allowedHosts.length} host(s)`})`);
        }
        else if (resolved.council.enabled) {
            ctx.logger.warn('secops: council requested but provenance is disabled — 丞相 needs claims to read; skipping');
        }
        const covered = registry.summary().filter((d) => d.ready > 0);
        ctx.logger.info(`secops: agent dispatch armed — ${covered.length} direction(s) with a ready agent ` +
            `(${covered.map((d) => `${d.direction}:${d.ready}/${d.total}`).join(', ')}); ` +
            `missing=${probe.missing.length === 0 ? 'none' : probe.missing.join(',')}`);
    }
    ctx.logger.info(`secops: scope=${resolved.allowedHosts.length} host(s), ` +
        `maxToolCalls=${resolved.maxToolCalls ?? '∞'}, ` +
        `maxSteps=${resolved.maxSteps ?? '∞'}`);
}
