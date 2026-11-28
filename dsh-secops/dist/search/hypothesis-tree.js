/**
 * 假设搜索树：在"下一步测什么"这件事上，用一个可解释的 bandit 替代模型直觉。
 *
 * ## 解决的问题
 *
 * 一轮作业里有几十条待验证假设，全部测一遍预算不够，随便挑又会重复踩坑。
 * 模型自己挑的顺序有两个毛病：**偏爱最近提到的那条**（近因偏差），
 * **避开之前失败的方向**（哪怕那次失败是环境问题）。
 *
 * ## 为什么是 UCB1 而不是完整 MCTS
 *
 * MCTS 需要一棵可以"模拟推演"的树——在渗透里你没有模拟器，无法 rollout。
 * 能做的只有"试了才知道"。所以这里退化成多臂老虎机：
 *
 *   分数 = 平均收益 + c × sqrt(ln(总尝试次数) / 该臂尝试次数)
 *
 * 前半截利用已知高收益的假设，后半截给尝试次数少的一个机会。
 * 两件事都有明确的行为含义，也都能在日志里解释给用户看——
 * 这比一个说不清理由的神经网络排序更符合"可审计"的要求。
 *
 * ## 依赖边
 *
 * 假设之间会有支撑关系（"B 字段可注入"要先于"B 字段导致越权"）。
 * 一条假设如果它的前置还没验证，现在就测它等于在沙地上盖房——
 * 所以 `next()` 会先把依赖未满足的排在后面，而不是直接剔除
 * （剔除会让整棵树在一条前置失败时全部作废）。
 */
export class HypothesisTree {
    nodes = new Map();
    exploration;
    totalPlays = 0;
    constructor(opts = {}) {
        this.exploration = opts.exploration ?? 1.2;
    }
    add(id, label, deps = []) {
        const existing = this.nodes.get(id);
        if (existing !== undefined)
            return existing;
        const node = { id, label, rewards: 0, plays: 0, deps: [...deps], settled: false };
        this.nodes.set(id, node);
        return node;
    }
    /** 标记为已定论（确认为真或被证伪），不再参与选择。 */
    settle(id) {
        const n = this.nodes.get(id);
        if (n !== undefined)
            n.settled = true;
    }
    /**
     * 记一次收益。收益取值建议：
     *   1.0 —— 拿到了新的强证据（推进了状态）
     *   0.5 —— 拿到弱证据或新线索
     *   0.0 —— 什么都没有，但确实试过了（这一笔很重要，它降低了该臂的均值）
     */
    reward(id, value) {
        const n = this.nodes.get(id);
        if (n === undefined)
            return;
        n.rewards += Math.max(0, Math.min(1, value));
        n.plays += 1;
        this.totalPlays += 1;
    }
    /** 依赖是否都已定论。 */
    depsReady(n) {
        return n.deps.every((d) => this.nodes.get(d)?.settled === true);
    }
    /**
     * 选下一个要测的假设。
     *
     * 排序规则（依次比较）：
     *   1. 未定论
     *   2. 依赖已满足（未满足的排在最后，但不剔除）
     *   3. UCB1 分数
     */
    next(limit = 5) {
        const open = [...this.nodes.values()].filter((n) => !n.settled);
        const scored = open.map((n) => {
            const ready = this.depsReady(n);
            const mean = n.plays === 0 ? 0 : n.rewards / n.plays;
            // 未试过的臂给无穷大，保证每个假设至少被试一次
            const ucb = n.plays === 0
                ? Number.POSITIVE_INFINITY
                : mean + this.exploration * Math.sqrt(Math.log(Math.max(1, this.totalPlays)) / n.plays);
            // 依赖未满足：整体降权，但仍然保留在列表里
            const score = ready ? ucb : ucb * 0.1;
            const reason = n.plays === 0
                ? 'never tried — the first attempt on any hypothesis is the cheapest information you can buy'
                : !ready
                    ? `waiting on ${n.deps.filter((d) => this.nodes.get(d)?.settled !== true).join(', ')}`
                    : `mean reward ${mean.toFixed(2)} over ${String(n.plays)} attempt(s)`;
            return { id: n.id, score, playCount: n.plays, meanReward: mean, reason };
        });
        scored.sort((a, b) => b.score - a.score);
        return scored.slice(0, Math.max(1, limit));
    }
    /** 一行摘要，给日志和复核用。 */
    summary() {
        let settled = 0;
        for (const n of this.nodes.values())
            if (n.settled)
                settled += 1;
        return { total: this.nodes.size, settled, open: this.nodes.size - settled, plays: this.totalPlays };
    }
    state() {
        return [...this.nodes.values()];
    }
}
