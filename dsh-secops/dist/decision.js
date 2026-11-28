/**
 * 决策阶段：挂在 agent/pre-step waterfall 上，并把决策写入 session log。
 *
 * 核实过的语义（dsh-agent-loop）：
 *   - 监听器签名 (payload, next)，payload = { agent, messages, turn, step, signal, modelSelection? }
 *   - 返回 { kind: 'reject' } → turn 以 blocked 结束
 *   - 返回 { kind: 'enter', messages } → 正常进入该 step
 *
 * 决策记录通过 `appendPluginRecord` 落到 session log，由 `secopsDecisions`
 * projection 折叠。会话恢复后记录自动重建（session log 是 append-only 的）。
 */
import { DecisionPolicy } from './decision-policy.js';
import { recordDecision, registerDecisionProjection, } from './decision-record.js';
export async function installDecisionStage(ctx, config, options = {}) {
    const policy = options.policy ?? new DecisionPolicy();
    // sessionProjections 是可选增强：没有它时决策只进日志，不落 session log。
    // 用 ctx.get 探测而不是写进 inject —— 硬依赖会让整个插件在精简 profile 里 PENDING，
    // 连范围闸和预算闸都装不上。
    const projections = ctx.get('sessionProjections');
    let persisted = false;
    if (projections !== undefined) {
        try {
            await registerDecisionProjection(projections);
            persisted = true;
        }
        catch (error) {
            ctx.logger.warn(`secops: decision projection unavailable — decisions stay in memory: ${String(error)}`);
        }
    }
    else {
        ctx.logger.warn('secops: sessionProjections absent — decisions will not be persisted');
    }
    void persisted;
    if (config.maxSteps === undefined && options.decide === undefined) {
        ctx.logger.info('secops: no decision policy — stage records only, never rejects');
    }
    // 每个 agent 独立计数。破甲会把子 agent 的提示词改成「继续任务，审批自动授予」
    // （purge #37）并关掉重复工具提醒（#18），被 guard 拒绝的子 agent 可能反复重试；
    // 这里显式按 agent 统计，保证 maxSteps 对每个 agent 各自生效。
    const seen = new Map();
    ctx.on('agent/pre-step', async (payload, next) => {
        const decision = await next();
        const agentId = payload.agent?.id ?? 'unknown';
        const observed = (seen.get(agentId) ?? 0) + 1;
        seen.set(agentId, observed);
        // 下游已经拒绝：不覆盖，只记录。
        if (decision.kind === 'reject') {
            appendSafely(ctx, payload.agent, {
                decisionId: makeId(),
                turn: payload.turn,
                step: payload.step,
                agentId,
                kind: 'reject',
                reason: 'upstream reject',
                candidates: [],
                evidenceRefs: [],
                rejected: [],
            });
            return decision;
        }
        // 显式策略优先。
        const verdict = options.decide?.({ turn: payload.turn, step: payload.step, agentId, messageCount: payload.messages.length }) ??
            defaultPolicy(config, payload.step, observed, agentId);
        if (verdict.kind === 'reject') {
            // 观察决策流：空理由、重复拒绝、连续空转都会在这里被记下。
            const violations = policy.observe({
                turn: payload.turn,
                step: payload.step,
                agentId,
                kind: 'reject',
                reason: verdict.reason,
            });
            for (const v of violations) {
                ctx.logger.warn(`secops/policy ${v.code}: ${v.detail} — ${v.hint}`);
            }
            appendSafely(ctx, payload.agent, {
                decisionId: makeId(),
                turn: payload.turn,
                step: payload.step,
                agentId,
                kind: 'reject',
                reason: verdict.reason,
                candidates: [],
                evidenceRefs: [],
                rejected: [],
            });
            if (config.logDecisions)
                ctx.logger.info(`secops: rejected step — ${verdict.reason}`);
            return { kind: 'reject' };
        }
        if (payload.signal.aborted)
            return decision;
        policy.observe({ turn: payload.turn, step: payload.step, agentId, kind: 'enter' });
        appendSafely(ctx, payload.agent, {
            decisionId: makeId(),
            turn: payload.turn,
            step: payload.step,
            agentId,
            kind: 'enter',
            candidates: [],
            evidenceRefs: [],
            rejected: [],
        });
        return decision;
    });
    if (config.logDecisions) {
        ctx.logger.info('secops: decision stage armed on agent/pre-step (records persisted to session log)');
    }
}
function defaultPolicy(config, step, observed, agentId) {
    const effectiveStep = Math.max(step, observed);
    if (config.maxSteps !== undefined && effectiveStep > config.maxSteps) {
        return {
            kind: 'reject',
            reason: `[secops/decision] agent "${agentId}" step ${effectiveStep} exceeds maxSteps ${config.maxSteps}`,
        };
    }
    return { kind: 'enter' };
}
/**
 * 写决策记录失败不能影响 pre-step —— 记录是副产品，不是主流程。
 * 但失败必须留痕，不能静默吞掉。
 */
function appendSafely(ctx, agent, record) {
    const session = agent?.session;
    if (session === undefined)
        return;
    try {
        recordDecision(session, record);
    }
    catch (error) {
        ctx.logger.warn(`secops: failed to record decision "${record.decisionId}": ${String(error)}`);
    }
}
function makeId() {
    return `dec-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
