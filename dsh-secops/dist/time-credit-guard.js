/**
 * 把时间信用挂到会话上。
 *
 * 三条线：
 *   计时 —— 第一次工具调用开始，不提前也不延后
 *   续期 —— 只认 ClaimStore 发来的进展事件（假设 / 强证据 / 独立路径 / 证伪）
 *   到点 —— 先提醒一次收尾，再耗尽时拒绝进入下一个 step
 *
 * 为什么在 pre-step 拒绝而不是直接杀进程：拒绝能让模型把当前结论说出来。
 * 直接杀会丢掉它已经掌握的东西，而「没解出来但知道哪些方向不通」本身有价值。
 */
import { randomUUID } from 'node:crypto';
import { msToHuman } from './time-credit.js';
function userMessage(text) {
    return {
        id: randomUUID(),
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text }],
    };
}
/** 进展事件 → 续期请求。事件来源是 ClaimStore，不是模型自述。 */
export function creditForProgress(credit, event, logger) {
    const decision = credit.grant(event.kind, event.claimId, event.detail);
    if (decision.granted) {
        logger?.info(`secops/time: +${msToHuman(decision.amount)} for ${event.kind} on ${event.claimId} — ` +
            `remaining ${msToHuman(decision.remaining)}`);
    }
}
export function installTimeCreditGuard(ctx, options) {
    const { credit, logger } = options;
    // 每个安装实例独立：模块级变量会让同一进程里的两个会话互相干扰。
    let expiryAnnounced = false;
    // 计时从第一个工具调用开始：模型只是在思考不该算作「消耗额度」。
    ctx.on('tools/pre-execute', async (_exec, next) => {
        credit.start();
        return next();
    });
    ctx.on('agent/pre-step', async (payload, next) => {
        const now = Date.now();
        if (credit.expired(now)) {
            // 已经结束的会话不该被反复拒绝：第二次以后放行，让收尾的话说得出来。
            if (!expiryAnnounced) {
                expiryAnnounced = true;
                logger?.warn(`secops/time: 额度耗尽（${msToHuman(credit.view(now).total)}），拒绝进入下一个 step`);
                return {
                    kind: 'enter',
                    messages: [
                        ...payload.messages,
                        userMessage(`[secops/time] 时间额度已经用完（基础 ${msToHuman(credit.view(now).base)} + 续期 ${msToHuman(credit.view(now).granted)}）。\n\n` +
                            `现在不要再发起任何工具调用。直接给出结案报告：已经确认了什么（附证据位置）、` +
                            `排除了哪些方向（附反例）、还差哪一步。写清楚「没解出来」比猜一个答案有用。`),
                    ],
                };
            }
            return {
                kind: 'enter',
                messages: [
                    ...payload.messages,
                    userMessage('[secops/time] 额度已耗尽。请直接输出结案报告，不要再调用工具。'),
                ],
            };
        }
        if (credit.shouldWarn(now)) {
            const left = msToHuman(credit.remaining(now));
            logger?.info(`secops/time: 剩余 ${left}，已提醒收尾`);
            return {
                kind: 'enter',
                messages: [
                    ...payload.messages,
                    userMessage(`[secops/time] 剩余 ${left}。\n\n` +
                        `时间只会在有实质进展时续期：提出带可证伪条件的假设（claim_assert）、` +
                        `交上一条真正触及断言的证据（claim_evidence）、把一个方向证伪掉（claim_refute）。` +
                        `重复同一个尝试不会续期。\n\n` +
                        `如果你手上已经有一个想法在反复试，把它写成假设并去攻击它的可证伪点；` +
                        `如果还没有，优先做能明确证伪或证实的那一件事。`),
                ],
            };
        }
        return next();
    });
}
// ── 模型侧工具 ───────────────────────────────────────────────
const TIME_SCHEMA = {
    type: 'object',
    properties: {
        started: { type: 'boolean' },
        base_ms: { type: 'number' },
        granted_ms: { type: 'number', description: 'Time earned from progress so far.' },
        total_ms: { type: 'number' },
        spent_ms: { type: 'number' },
        remaining_ms: { type: 'number' },
        expires_in: { type: 'string' },
        grants: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    kind: { type: 'string' },
                    claim: { type: 'string' },
                    detail: { type: 'string' },
                    amount_ms: { type: 'number' },
                },
                required: ['kind', 'claim', 'amount_ms'],
            },
        },
    },
    required: ['started', 'base_ms', 'granted_ms', 'total_ms', 'spent_ms', 'remaining_ms'],
};
/**
 * 让模型能看见自己的时间账户。
 *
 * 不是为了透明，是为了让它能规划：知道还剩 8 分钟、知道上一条证据挣了 10 分钟，
 * 才会在「再试一次」和「换个方向」之间做出选择。看不见余额的人不会省着花。
 */
export function timeCreditTools(credit) {
    return [
        {
            name: 'time_budget',
            description: 'Check the remaining working time for this session. Time is granted, not fixed: the base allowance runs out, ' +
                'and each piece of real progress buys more — a falsifiable hypothesis with a falsifier (claim_assert), ' +
                'evidence that passes the anchor check (claim_evidence), an independent path, or a refutation (claim_refute). ' +
                'Repeating the same attempt earns nothing. When time runs out the session stops and you must report what you established.',
            parameters: { type: 'object', properties: {} },
            output: {
                schema: TIME_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    const lines = [
                        `remaining=${msToHuman(Number(r.remaining_ms ?? 0))}`,
                        `total=${msToHuman(Number(r.total_ms ?? 0))} (base ${msToHuman(Number(r.base_ms ?? 0))} + earned ${msToHuman(Number(r.granted_ms ?? 0))})`,
                        `spent=${msToHuman(Number(r.spent_ms ?? 0))}`,
                    ];
                    const grants = (r.grants ?? []);
                    if (grants.length === 0) {
                        lines.push('earned=nothing yet — no hypothesis or evidence has landed');
                    }
                    else {
                        lines.push('earned so far:');
                        for (const g of grants) {
                            lines.push(`  +${msToHuman(Number(g.amount_ms ?? 0))} ${String(g.kind)} on ${String(g.claim)}`);
                        }
                    }
                    return [{ type: 'text', text: lines.join('\n') }];
                },
            },
            async execute() {
                const v = credit.view();
                return {
                    started: v.started,
                    base_ms: v.base,
                    granted_ms: v.granted,
                    total_ms: v.total,
                    spent_ms: v.spent,
                    remaining_ms: v.remaining,
                    expires_in: msToHuman(v.remaining),
                    grants: v.grants.map((g) => ({
                        kind: g.kind,
                        claim: g.claimId,
                        detail: g.detail,
                        amount_ms: g.amount,
                    })),
                };
            },
        },
    ];
}
export function installTimeCreditTools(ctx, credit) {
    for (const tool of timeCreditTools(credit))
        ctx.tools.register(tool);
}
