/**
 * 决策纪律：把"判断与决策的质量"变成可检测的模式，而不是靠模型自觉。
 *
 * 为什么在 pre-step 层做：这是唯一能在每一步之前看到「发生了什么」的地方。
 * 但它看不到模型的意图，所以这里的规则全部基于**可观测的决策流**：
 *   - 拒绝有没有说清理由
 *   - 是不是在反复拒绝同一件事（卡死）
 *   - 是不是长时间只拒绝不前进（空转）
 *
 * 三条规则都不试图判断"决策对不对"——那需要领域知识。它们只判断
 * "决策过程是否失能"，这是工程上能确定的部分。
 */
/** reject 理由的最短长度。低于此值视为「没说清」。 */
export const MIN_REASON_LENGTH = 10;
/** 同一理由前缀连续出现多少次算卡死。 */
export const REPEAT_WINDOW = 3;
/** 同一 agent 连续多少步全是 reject 算空转。 */
export const STALL_WINDOW = 5;
/** 判定"同一理由"时比较的前缀长度。 */
const REASON_PREFIX = 32;
/**
 * 有状态的决策观测器。
 *
 * 只读不判：它不否决决策，只记录违规并把违规变成对模型的可见反馈。
 * 「否决」发生在 pre-step 的返回里，由调用方决定。
 */
export class DecisionPolicy {
    agents = new Map();
    total = 0;
    entered = 0;
    rejected = 0;
    emptyReasons = 0;
    violations = [];
    stateOf(agentId) {
        let s = this.agents.get(agentId);
        if (s === undefined) {
            s = { lastReasonKey: undefined, repeat: 0, consecutiveRejects: 0, maxRepeat: 0, maxStall: 0 };
            this.agents.set(agentId, s);
        }
        return s;
    }
    /** 记录一次决策，返回本次触发的违规（可能为空）。 */
    observe(sample) {
        const state = this.stateOf(sample.agentId);
        const hit = [];
        this.total += 1;
        if (sample.kind === 'enter') {
            this.entered += 1;
            state.consecutiveRejects = 0;
            state.lastReasonKey = undefined;
            state.repeat = 0;
            return hit;
        }
        this.rejected += 1;
        state.consecutiveRejects += 1;
        state.maxStall = Math.max(state.maxStall, state.consecutiveRejects);
        const reason = (sample.reason ?? '').trim();
        // 规则 1：拒绝必须说清理由
        if (reason.length < MIN_REASON_LENGTH) {
            this.emptyReasons += 1;
            hit.push({
                code: 'EMPTY_REASON',
                agentId: sample.agentId,
                detail: `reject at turn ${sample.turn} step ${sample.step} has a ${reason.length}-char reason (min ${MIN_REASON_LENGTH})`,
                hint: 'state the concrete blocking condition, not "cannot proceed"',
            });
        }
        // 规则 2：同一理由反复出现 = 卡死
        const key = reason.slice(0, REASON_PREFIX);
        if (key.length > 0 && key === state.lastReasonKey) {
            state.repeat += 1;
        }
        else {
            state.repeat = 1;
            state.lastReasonKey = key;
        }
        state.maxRepeat = Math.max(state.maxRepeat, state.repeat);
        if (state.repeat >= REPEAT_WINDOW) {
            hit.push({
                code: 'REPEATED_REJECTION',
                agentId: sample.agentId,
                detail: `the same rejection reason occurred ${state.repeat} times in a row`,
                hint: 'a repeated rejection is a signal the approach is wrong — change the method, not the wording',
            });
        }
        // 规则 3：只拒绝不前进 = 空转
        if (state.consecutiveRejects >= STALL_WINDOW) {
            hit.push({
                code: 'STALLED',
                agentId: sample.agentId,
                detail: `${state.consecutiveRejects} consecutive steps rejected without entering one`,
                hint: 'stop retrying; summarize what is blocked and hand it back to the operator',
            });
        }
        this.violations.push(...hit);
        return hit;
    }
    /** 生成审计报告。 */
    audit() {
        let worstRepeat = 0;
        let worstStall = 0;
        for (const s of this.agents.values()) {
            worstRepeat = Math.max(worstRepeat, s.maxRepeat);
            worstStall = Math.max(worstStall, s.maxStall);
        }
        const verdict = worstStall >= STALL_WINDOW || worstRepeat >= REPEAT_WINDOW
            ? 'stalled'
            : this.emptyReasons > 0
                ? 'degraded'
                : 'ok';
        return {
            total: this.total,
            entered: this.entered,
            rejected: this.rejected,
            emptyReasons: this.emptyReasons,
            worstRepeat,
            worstStall,
            verdict,
            violations: this.violations.slice(-20),
        };
    }
    /** 最近一次违规（诊断用）。 */
    lastViolation() {
        return this.violations[this.violations.length - 1];
    }
}
