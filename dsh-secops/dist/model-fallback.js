/**
 * Model Fallback：provider 失败时自动切到备用路由。
 *
 * 为什么需要：DSH 只有 retry（同一 provider 重试），没有 failover。
 * 当一个 provider 限流、宕机或鉴权失效时，retry 只会把同样的失败重放 N 次。
 *
 * 落点是两个现成接缝：
 *   - `agent/request-error` waterfall：拿到失败详情，决定是否切换并返回 retry
 *   - `agent/request` waterfall：返回替换后的 LlmCallConfig，把下一次请求指到备用路由
 *
 * 关键设计：**只对可恢复的失败切换**。上下文超限、用户取消、内容拒绝这些
 * 换 provider 也解决不了，切了反而把真实问题掩盖成"所有 provider 都失败"。
 */
const DEFAULT_MAX_SWITCHES = 3;
/**
 * 默认判定：哪些失败值得换 provider。
 *
 * 不切的情况很关键：
 *   - 上下文超限（换 provider 也装不下）
 *   - 用户取消（不是 provider 的问题）
 *   - 内容策略拒绝（换 provider 是规避审核，不是修复）
 */
export function shouldFailover(failure) {
    const code = failure.code.toUpperCase();
    // 明确不该切的
    if (code.includes('CONTEXT_WINDOW') || code.includes('QUOTA'))
        return false;
    if (code.includes('ABORT') || code.includes('CANCEL'))
        return false;
    if (code.includes('REFUSAL') || code.includes('CONTENT'))
        return false;
    if (code.includes('INVALID_CREDENTIAL')) {
        // 鉴权失败值得切：换 provider 可能用另一套凭据
        return true;
    }
    // HTTP 语义
    const status = failure.status;
    if (status !== undefined) {
        if (status === 429)
            return true;
        if (status >= 500 && status <= 599)
            return true;
        if (status === 401 || status === 403)
            return true;
        if (status === 408)
            return true;
        return false;
    }
    // 传输层
    // 注意 ETIMEDOUT 里是 TIMEDOUT 不是 TIMEOUT，两个都要覆盖
    if (/TIMEOUT|TIMEDOUT|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|SOCKET|EPIPE/.test(code))
        return true;
    if (/RATE[_ ]?LIMIT|OVERLOAD|UNAVAILABLE/.test(code))
        return true;
    return false;
}
export class ModelFallback {
    /**
     * provider 维度的全局冷却表。
     *
     * 早先只有按 agentId 索引的状态。编排器每轮/每次派发都会生成新的 agentId
     * （worker-r3、worker-r4…），于是**每个新子 Agent 都从 cursor=0 重新撞一次
     * 已经 429 的主路由**。主路由宕机时，这个放大器会把一次故障变成 N 次重试。
     *
     * 这份表跨 agentId 共享：某个 provider 失败到阈值就全局冷却一段时间，
     * 冷却期内任何 agent 都直接跳过它。
     */
    providerCooldown = new Map();
    /** 某个 provider 是否在全局冷却中。 */
    providerCooling(key) {
        const st = this.providerCooldown.get(key);
        if (st === undefined)
            return false;
        if (st.until <= Date.now()) {
            this.providerCooldown.delete(key);
            return false;
        }
        return true;
    }
    /**
     * 记录一次 provider 失败。达到阈值后进入全局冷却。
     *
     * 阈值与冷却时长走保守值：cooling 太短起不到作用，太长会让整个 provider
     * 被永久拉黑。5 分钟是"够绕过一个限流窗口、又不会错过恢复"的折中。
     */
    noteProviderFault(provider, reason) {
        const prev = this.providerCooldown.get(provider);
        const until = Date.now() + 5 * 60_000;
        this.providerCooldown.set(provider, { until, lastFault: reason.slice(0, 120) });
        void prev;
    }
    routes;
    maxSwitches;
    decide;
    states = new Map();
    records = [];
    constructor(options) {
        if (options.routes.length === 0)
            throw new Error('model-fallback: routes must not be empty');
        this.routes = options.routes;
        this.maxSwitches = Math.max(0, options.maxSwitches ?? DEFAULT_MAX_SWITCHES);
        this.decide = options.shouldFailover ?? shouldFailover;
    }
    get enabled() {
        return this.routes.length > 1;
    }
    stateOf(agentId) {
        let s = this.states.get(agentId);
        if (s === undefined) {
            s = { cursor: 0, switches: 0 };
            this.states.set(agentId, s);
        }
        return s;
    }
    /**
     * 处理一次请求失败。返回 true 表示已经切换到备用路由，调用方应 retry。
     *
     * 幂等：同一 agent 连续失败会逐级下移，用尽后就返回 false（交回原有错误处理）。
     */
    onRequestError(agentId, failure) {
        if (!this.enabled)
            return false;
        const state = this.stateOf(agentId);
        if (state.switches >= this.maxSwitches)
            return false;
        if (!this.decide(failure))
            return false;
        if (state.cursor >= this.routes.length - 1)
            return false;
        const from = this.routes[state.cursor];
        // 记一笔 provider 级故障：别的 agentId 下次选路时会跳过它
        this.noteProviderFault(`${from.provider}/${from.model}`, failure.code);
        state.cursor += 1;
        state.switches += 1;
        const to = this.routes[state.cursor];
        this.records.push({
            agentId,
            from: `${from.provider}/${from.model}`,
            to: `${to.provider}/${to.model}`,
            code: failure.code,
            ...(failure.status === undefined ? {} : { status: failure.status }),
            at: Date.now(),
        });
        return true;
    }
    /**
     * 在 `agent/request` 里调用：给出应当使用的路由。
     *
     * 返回 undefined 表示不要改（沿用原配置）。
     */
    routeFor(agentId, current) {
        if (!this.enabled)
            return undefined;
        const state = this.stateOf(agentId);
        // 用 cursor 判断是否已偏离主路由，而不是 switches ——
        // onSuccess 会把 switches 归零（重新获得切换额度），但不应该把路由退回去。
        // 从 cursor 往后找第一个**不在全局冷却中**的路由。
        //
        // 这一步必须在 `cursor === 0` 的提前返回之前：新 agentId 的 cursor 恒为 0，
        // 如果先返回 undefined，它就永远走主路由——而主路由可能正被别的 agent
        // 撞成 429 处于冷却中。provider 的故障是全局事实，不该按 agent 各记一遍。
        let idx = state.cursor;
        while (idx < this.routes.length) {
            const cand = this.routes[idx];
            if (cand !== undefined && !this.providerCooling(`${cand.provider}/${cand.model}`))
                break;
            idx += 1;
        }
        if (idx >= this.routes.length)
            return undefined;
        // 没有任何切换、也没跳过冷却 → 不改配置
        if (idx === 0 && state.cursor === 0)
            return undefined;
        state.cursor = idx;
        const target = this.routes[state.cursor];
        if (target === undefined)
            return undefined;
        if (target.provider === current.provider && target.model === current.model)
            return undefined;
        return { provider: target.provider, model: target.model };
    }
    /** 成功一次后重置计数（但不回退路由：回到坏 provider 会再失败一轮）。 */
    onSuccess(agentId) {
        const state = this.states.get(agentId);
        if (state !== undefined)
            state.switches = 0;
    }
    /** 切换记录，供诊断与审计。 */
    history() {
        return this.records;
    }
    /** 当前各 agent 的路由状态。 */
    snapshot() {
        return [...this.states.entries()].map(([agentId, s]) => ({
            agentId,
            route: `${this.routes[s.cursor]?.provider}/${this.routes[s.cursor]?.model}`,
            switches: s.switches,
        }));
    }
}
