/**
 * 假设排序工具：把"下一步测什么"变成一个能解释的排序，而不是模型的直觉。
 *
 * ## 为什么这需要工具而不是提示词
 *
 * 一轮作业里几十条待验证假设，全测预算不够。让模型自己挑有两个可预测的偏差：
 * **近因偏差**（偏爱对话里最近提到的那条）和**回避失败**（不碰之前失败的方向，
 * 哪怕失败原因是环境抖动）。这两种偏差在日志里都表现为"怎么老在测同一类东西"。
 *
 * 排序用 UCB1：平均收益 + 探索项。两半都有明确含义——
 * 前者利用已知高产的假设，后者保证没试过的假设至少被试一次。
 * 试过的次数用"该断言已有的证据条数"来代理，所以不需要额外的持久化状态：
 * 账本本身就是记忆。
 *
 * ## 为什么不用完整 MCTS
 *
 * MCTS 依赖 rollout（推演）。渗透里没有模拟器，推演不出来，所以退化成 bandit。
 * 少一层结构换来的是"每一步都能解释给人看"——这比一个说不清理由的排序更该要。
 */
const EXPLORATION = 1.2;
/** 一条断言已经"花掉"的尝试次数：证据条数（对照与反驳也算试过）。 */
function attemptsOf(c) {
    return c.evidence.length;
}
/** 归一化收益：强证据按 1 计，弱证据按 0.5，驳回/对照不计分。 */
function rewardOf(c) {
    let r = 0;
    for (const e of c.evidence) {
        if (e.role === 'refutation')
            continue;
        if (e.relevance?.strength === 'strong')
            r += 1;
        else
            r += 0.5;
    }
    return Math.min(r, Math.max(1, attemptsOf(c)));
}
/** 对全部未定论假设排序。 */
export function rankHypotheses(claims, limit = 5) {
    const open = claims.filter((c) => c.status === 'hypothesis' || c.status === 'partial' || c.status === 'inference');
    const totalPlays = open.reduce((s, c) => s + attemptsOf(c), 0);
    const scored = open.map((c) => {
        const plays = attemptsOf(c);
        const rewards = rewardOf(c);
        const mean = plays === 0 ? 0 : rewards / plays;
        const ucb = plays === 0
            ? Number.POSITIVE_INFINITY
            : mean + EXPLORATION * Math.sqrt(Math.log(Math.max(1, totalPlays)) / plays);
        const reason = plays === 0
            ? 'untouched — the first attempt on any hypothesis is the cheapest information available'
            : `mean reward ${mean.toFixed(2)} over ${String(plays)} attempt(s)`;
        return {
            id: c.id,
            claim: c.claim,
            status: c.status,
            attempts: plays,
            meanReward: mean,
            score: ucb,
            reason,
        };
    });
    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, Math.max(1, limit));
}
const NEXT_SCHEMA = {
    type: 'object',
    properties: {
        considered: { type: 'number' },
        settled: { type: 'number' },
        picks: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    claim_id: { type: 'string' },
                    claim: { type: 'string' },
                    status: { type: 'string' },
                    attempts: { type: 'number' },
                    mean_reward: { type: 'number' },
                    score: { type: 'number' },
                    reason: { type: 'string' },
                },
                required: ['claim_id', 'claim', 'status', 'score', 'reason'],
            },
        },
        hint: { type: 'string' },
    },
    required: ['considered', 'settled', 'picks'],
};
export function searchTools(store) {
    const nextTool = {
        name: 'hypothesis_next',
        description: 'Rank the open claims and tell you which to attack next, with a reason for each pick. ' +
            'The ranking is UCB1 over (attempts so far, reward so far), where attempts are derived from how much ' +
            'evidence each claim already carries — so the store itself is the memory and nothing needs persisting. ' +
            'Untouched claims come first (cheapest information), then claims with a good evidence yield, and the ' +
            'exploration term keeps a claim from being starved just because one attempt failed. ' +
            'This exists because picking by intuition reproduces two predictable biases: recency and failure-aversion.',
        parameters: {
            type: 'object',
            properties: {
                limit: { type: 'number', description: 'How many to return (default 5).' },
            },
        },
        output: {
            schema: NEXT_SCHEMA,
            render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
        },
        execute: async (args) => {
            const a = (args ?? {});
            const all = store.query();
            const settled = all.filter((c) => c.status === 'confirmed' || c.status === 'refuted').length;
            const picks = rankHypotheses(all, a.limit ?? 5);
            return {
                considered: all.length - settled,
                settled,
                picks: picks.map((p) => ({
                    claim_id: p.id,
                    claim: p.claim,
                    status: p.status,
                    attempts: p.attempts,
                    mean_reward: Number(p.meanReward.toFixed(3)),
                    score: Number.isFinite(p.score) ? Number(p.score.toFixed(3)) : 999,
                    reason: p.reason,
                })),
                ...(picks.length === 0
                    ? { hint: 'no open claims — assert new hypotheses before asking what to test next' }
                    : {}),
            };
        },
    };
    return [nextTool];
}
