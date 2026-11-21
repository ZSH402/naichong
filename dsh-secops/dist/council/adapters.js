/**
 * 执行体适配器：把三种不同的东西塞进同一个 TaskContract。
 *
 * 现在只有 CLI 一种真正可用，但接口必须先立起来——否则「统一任务契约」
 * 只是一句口号，将来加 subagent 或自研 worker 时又要在下游到处加分支。
 */
import { buildEvidenceManifest } from "./contract.js";
import { COST_WEIGHT } from "../agent-registry.js";
/** 调度器的结果 → 任务契约的终态。 */
function mapOutcome(stopReason, settled) {
    if (settled)
        return 'settled';
    switch (stopReason) {
        case 'inconclusive':
            return 'inconclusive';
        case 'aborted':
            return 'failed';
        default:
            // no-fit / cost-budget / fault-circuit / exhausted / deadline / max-attempts
            // 都表示「没拿到结论就停了」，归为 failed 会让统计失真，
            // 但它们确实不是 inconclusive（那是跑通了没定论）。用 blocked 更准确：
            // 是调度层主动不跑了，不是执行体说不知道。
            return stopReason === 'no-fit' || stopReason === 'cost-budget' || stopReason === 'fault-circuit'
                ? 'blocked'
                : 'failed';
    }
}
/**
 * CLI 工具适配器：走 DirectionalDispatcher（内含形态选择、降级、止损）。
 *
 * 注意它没有「自己再选一次 agent」的逻辑——选谁、换不换、停不停都在
 * dispatcher 里，适配器只负责把契约喂进去、把结果和证据清单端出来。
 * 分散在多处做同一件事，是这类系统最后没人敢改的主因。
 */
export function createCliToolAdapter(deps) {
    return {
        kind: 'code-tool',
        describe: '本地确定性工具（nuclei/semgrep/corvus/rabin2 等），有结构化判据的走这条',
        async execute(contract, ctx) {
            const startedAt = Date.now();
            const outcome = await deps.dispatcher.dispatch({
                direction: contract.direction,
                target: contract.target,
                ...(contract.timeoutMs === undefined ? {} : { timeoutMs: contract.timeoutMs }),
                ...(contract.claimId === undefined ? {} : { claimId: contract.claimId }),
                ...(contract.preferredAgentId === undefined ? {} : { preferAgentId: contract.preferredAgentId }),
            }, ctx.signal);
            const lastAttempt = outcome.attempts[outcome.attempts.length - 1];
            const evidenceDir = lastAttempt?.evidenceDir;
            const manifest = evidenceDir !== undefined ? buildEvidenceManifest(evidenceDir) : undefined;
            const mapped = mapOutcome(outcome.stopReason, outcome.settled);
            // 实际代价按已发生的尝试累加：中途被预算挡住时，前面那几次是真花了的。
            let actualCost = 0;
            for (const a of outcome.attempts)
                actualCost += COST_WEIGHT[(a.cost ?? 'moderate')];
            deps.censorSettle?.(contract, mapped === 'settled' ? 'ok' : mapped === 'failed' ? 'fault' : 'neutral');
            return {
                contract,
                outcome: mapped,
                ...(outcome.found === undefined ? {} : { found: outcome.found }),
                ...(outcome.findingClass === undefined ? {} : { findingClass: outcome.findingClass }),
                ...(outcome.detail === undefined ? {} : { detail: outcome.detail }),
                ...(outcome.by === undefined ? {} : { agentId: outcome.by }),
                ...(evidenceDir === undefined ? {} : { evidenceDir }),
                ...(manifest === undefined ? {} : { manifest }),
                // reason 必须永远有值：blocked 但说不出为什么，下游只能靠猜，
                // 而「靠猜」正是这一层存在的理由。
                reason: outcome.failureReason === undefined
                    ? `stop_reason=${outcome.stopReason}${outcome.untried === undefined || outcome.untried.length === 0 ? '' : ` untried=${outcome.untried.map((u) => `${u.agent}(${u.fitness})`).join(',')}`}`
                    : `${outcome.stopReason}: ${outcome.failureReason}`,
                durationMs: Date.now() - startedAt,
                cost: actualCost,
                attempts: outcome.attempts.map((a) => ({
                    agent: a.agentId,
                    result: a.result,
                    fitness: a.fitness,
                })),
            };
        },
    };
}
/**
 * 占位：专项 agent 适配器。
 *
 * 不伪装成可用——execution layer 目前只驱动 CLI，subagent provider 还没接。
 * 留着接口是为了让 plan 能明确地说「这条本该走 agent，但这条通道没通」，
 * 而不是悄悄退化成别的。
 */
export function createAgentAdapter(deps) {
    return {
        kind: 'agent',
        describe: deps.available ? '专项 agent（subagent provider）' : `专项 agent 通道未接通${deps.reason === undefined ? '' : `：${deps.reason}`}`,
        async execute(contract, _ctx) {
            return {
                contract,
                outcome: 'refused',
                reason: deps.reason ?? 'agent adapter is not wired to a subagent provider yet',
                durationMs: 0,
                cost: 0,
            };
        },
    };
}
/** 占位：自研 worker 适配器。契约先立，实现后补。 */
export function createWorkerAdapter(deps) {
    return {
        kind: 'worker',
        describe: `自研 worker（已注册 ${deps.handlers.size} 个）`,
        async execute(contract, ctx) {
            const handler = deps.handlers.get(contract.direction);
            if (handler === undefined) {
                return { contract, outcome: 'refused', reason: `no worker registered for ${contract.direction}`, durationMs: 0, cost: 0 };
            }
            const startedAt = Date.now();
            try {
                const out = await handler(contract);
                const manifest = out.evidenceDir === undefined ? undefined : buildEvidenceManifest(out.evidenceDir);
                return {
                    contract,
                    outcome: 'settled',
                    found: out.found,
                    ...(out.detail === undefined ? {} : { detail: out.detail }),
                    ...(out.evidenceDir === undefined ? {} : { evidenceDir: out.evidenceDir }),
                    ...(manifest === undefined ? {} : { manifest }),
                    durationMs: Date.now() - startedAt,
                    cost: contract.estimatedCost,
                };
            }
            catch (error) {
                if (ctx.signal.aborted) {
                    return { contract, outcome: 'failed', reason: 'aborted', durationMs: Date.now() - startedAt, cost: 0 };
                }
                return { contract, outcome: 'failed', reason: String(error), durationMs: Date.now() - startedAt, cost: 0 };
            }
        },
    };
}
/** 给某方向挑 adapter：worker 优先（更贴业务），其次 code-tool。 */
export function pickAdapterKind(direction, kinds) {
    if (kinds.includes('worker'))
        return 'worker';
    if (kinds.includes('code-tool'))
        return 'code-tool';
    return 'agent';
}
/** 从注册表取一个方向的预估代价：取最便宜可用候选的权重。 */
export function estimateCost(registry, direction, target) {
    const pool = registry.available(direction, undefined);
    if (pool.length === 0)
        return 1;
    let best = Number.POSITIVE_INFINITY;
    for (const c of pool)
        best = Math.min(best, COST_WEIGHT[c.cost ?? 'moderate']);
    return Number.isFinite(best) ? best : 1;
}
