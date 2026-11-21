/**
 * 停滞检测：连续做同一件事的变体，却期望不同结果。
 *
 * 真实观测：两轮共 141 次工具调用解一道逆向题，从第 40 次起就进入了
 * 「换个爆破顺序再试一次」的循环（truth→truth2→support→support2→anf→bruteorder）。
 * 每一轮都是同一个假设的变体，一次都没回头质疑假设本身，最后跑满 45 分钟超时。
 *
 * 系统里没有任何机制在看这件事。DecisionPolicy 的 STALL_WINDOW 管的是
 * 「连续拒绝」，管不到「连续同方向尝试无产出」——后者才是真正烧钱的那种空转。
 *
 * 这里不阻止调用（阻止会让 agent 彻底卡死），只在对的时机插一句话，
 * 要求它把假设写下来并直接去攻击可证伪的那一点。
 */
import { randomUUID } from 'node:crypto';
/** 构造一条 user 消息。id 必须是唯一且稳定的字符串品牌，直接用 uuid。 */
function userMessage(text) {
    return {
        id: randomUUID(),
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text }],
    };
}
/** 一次调用的指纹。只取工具名 + 参数前缀：细微差异（换顺序、换文件名）不该算新尝试。 */
function fingerprint(name, args) {
    let shape = '';
    try {
        shape = JSON.stringify(args);
    }
    catch {
        shape = String(args);
    }
    // 去掉易变部分：十六进制长串、所有数字。
    // 为什么要连小数字一起去掉：真实停滞长这样——
    //   python3 brute.py --order 0 / --order 1 / --order 2 / --order 3
    // 参数各不相同，但那是同一个想法的四个版本。按字面比指纹会把它当成
    // 「一直在做不同的事」，而这恰恰是两轮实战里烧掉一小时的那种循环。
    const normalized = shape
        .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
        .replace(/\d+/g, '<n>')
        .slice(0, 160);
    return `${name}::${normalized}`;
}
export const DEFAULT_STALL = {
    window: 12,
    threshold: 5,
    cooldown: 10,
};
/**
 * 搜索/枚举类工作的特征。
 *
 * 需要单列一档，因为它和「同一命令换个参数」不是一回事：模型可能每次写的脚本
 * 都不同、文件都不同，但方法同一类——都在用蛮力靠近答案。真实观测里，
 * 这种状态可以持续几小时而每一轮的指纹都不重复，靠指纹去重完全看不出来。
 */
const SEARCH_HINTS = [
    { re: /\bsim(ulate|ulation)?\b/i, label: 'simulate' },
    { re: /\bbrute[-_ ]?force\b|\bbrute\b/i, label: 'brute-force' },
    { re: /\benumerate\b|\benum\b/i, label: 'enumerate' },
    { re: /\bpermutation|itertools\.(permutations|product|combinations)/i, label: 'permutation' },
    { re: /for\s+\w+\s+in\s+range\(.*range\(/i, label: 'nested-loop' },
    { re: /\bdecod(e|ing)\s+(all|every)\b/i, label: 'try-all' },
    { re: /\bfor\s+\w+\s+in\s+range\(\s*2\s*\*\*/i, label: 'exhaustive-range' },
];
export function detectSearchApproach(text) {
    for (const h of SEARCH_HINTS)
        if (h.re.test(text))
            return h.label;
    return undefined;
}
export class StallDetector {
    config;
    history = [];
    lastNudgeAtCall = -Infinity;
    nudges = 0;
    constructor(config = {}) {
        this.config = { ...DEFAULT_STALL, ...config };
    }
    searchTrail = [];
    /** 记一次「编写搜索类脚本」的迹象。返回连续次数。 */
    noteApproach(text) {
        const label = detectSearchApproach(text);
        if (label === undefined)
            return undefined;
        this.searchTrail.push(label);
        if (this.searchTrail.length > 8)
            this.searchTrail.shift();
        return { label, streak: this.searchTrail.length };
    }
    /** 连续写搜索类脚本是否已经到该提醒的程度。 */
    searchStalled(threshold = 3) {
        const recent = this.searchTrail.slice(-threshold);
        if (recent.length < threshold)
            return undefined;
        return { label: recent[recent.length - 1], streak: this.searchTrail.length };
    }
    record(name, args) {
        this.history.push(fingerprint(name, args));
        // 只保留窗口大小的历史；更早的重复不该影响判断
        const cap = this.config.window * 2;
        if (this.history.length > cap)
            this.history.splice(0, this.history.length - cap);
    }
    /** 判断当前是否停滞。纯读取，不改状态。 */
    inspect() {
        const recent = this.history.slice(-this.config.window);
        if (recent.length < this.config.threshold)
            return { stalled: false };
        const counts = new Map();
        for (const fp of recent)
            counts.set(fp, (counts.get(fp) ?? 0) + 1);
        let worst = '';
        let hits = 0;
        for (const [fp, n] of counts) {
            if (n > hits) {
                hits = n;
                worst = fp;
            }
        }
        if (hits < this.config.threshold)
            return { stalled: false };
        return {
            stalled: true,
            signature: worst.split('::')[0] === worst ? worst : worst.slice(0, 120),
            hits,
            window: recent.length,
        };
    }
    /**
     * 是否该提醒。有冷却：同一个循环里每步都喊一句，等于噪音。
     */
    shouldNudge() {
        const verdict = this.inspect();
        if (!verdict.stalled)
            return undefined;
        if (this.history.length - this.lastNudgeAtCall < this.config.cooldown)
            return undefined;
        this.lastNudgeAtCall = this.history.length;
        this.nudges += 1;
        return verdict;
    }
    /** 诊断用。 */
    stats() {
        return { calls: this.history.length, nudges: this.nudges };
    }
}
/** 提醒文本。写成「下一步做什么」，不是「你卡住了」——后者只会让模型道歉。 */
export function stallReminder(verdict) {
    return (`[secops/stall] 最近 ${String(verdict.window)} 次调用里有 ${String(verdict.hits)} 次是同一操作的变体。` +
        `继续调整这些变体不会改变结论——你需要的是一个能推翻当前想法的新观测，而不是同一想法的第 ${String(verdict.hits)} 个版本。\n\n` +
        `现在就做：用 claim_assert 把当前假设写成一句可证伪的话（它必须具体到「什么观测会让它不成立」），` +
        `然后直接去取那个观测。如果取不到，说明假设本身没法验证，换一个假设。`);
}
/** 范式级提醒：问题不在参数，在方法。 */
export function approachReminder(label, streak) {
    return (`[secops/stall] 你已经连续 ${String(streak)} 次在写搜索/枚举类的东西（最近一次：${label}）。\n\n` +
        `这类问题的症结通常不是实现不够快，而是**搜索空间本身不该被搜**。先回答一个问题：` +
        `如果穷举到底，空间有多大？如果是 2^256 这种量级，优化循环永远到不了；那说明答案不该靠试出来，` +
        `而该靠推出来——把约束写下来直接解，或者找出让它可解的结构（分层、可分解、有对称性）。\n\n` +
        `另一个自检：你现在的结论如果建立在自写的解析器上，先拿一个已知答案的输入验证那个解析器本身。` +
        `工具出错比思路出错更难发现，而且它会让你在错误的模型上推论很久。`);
}
/**
 * 挂上检测器：`tools/pre-execute` 记录，`agent/pre-step` 注入提醒。
 *
 * 不拦调用。拦截在长任务里是灾难——agent 会转而用别的方式绕过，
 * 而真正的目标（让它换假设）没达成。
 */
export function installStallGuard(ctx, options = {}) {
    const detector = new StallDetector(options.config);
    let pendingApproach;
    ctx.on('tools/pre-execute', async (exec, next) => {
        if (typeof exec.name === 'string')
            detector.record(exec.name, exec.arguments);
        // 写脚本的动作本身是信号：看看它这次在写什么类别的东西
        const args = exec.arguments;
        if (typeof args?.command === 'string') {
            detector.noteApproach(args.command);
            const stalled = detector.searchStalled();
            if (stalled !== undefined && pendingApproach === undefined) {
                pendingApproach = approachReminder(stalled.label, stalled.streak);
                options.logger?.warn(`secops/stall: 连续 ${String(stalled.streak)} 次搜索类脚本，将注入范式提醒`);
                // 连续写搜索类脚本是最典型的「用蛮力代替换假设」，扣时间。
                const charged = options.credit?.debit('repeat-approach', `${stalled.label} ×${String(stalled.streak)}`);
                if (charged?.granted === true) {
                    options.logger?.warn(`secops/stall: 扣减 ${String(Math.round(-charged.amount / 1000))}s 时间信用（连续搜索类脚本）`);
                }
            }
        }
        return next();
    });
    ctx.on('agent/pre-step', async (payload, next) => {
        const decision = await next();
        if (decision.kind !== 'enter')
            return decision;
        // 范式级提醒优先：它比「换个参数」重要得多，先递这条。
        if (pendingApproach !== undefined) {
            const note = pendingApproach;
            pendingApproach = undefined;
            return { kind: 'enter', messages: [...decision.messages, userMessage(note)] };
        }
        const verdict = detector.shouldNudge();
        if (verdict === undefined)
            return decision;
        options.logger?.warn(`secops/stall: 连续 ${String(verdict.hits)} 次相似调用，已注入换假设提醒（第 ${String(detector.stats().nudges)} 次）`);
        const charged = options.credit?.debit('stall', `${String(verdict.hits)} similar calls (${String(verdict.signature ?? '')})`);
        if (charged?.granted === true) {
            options.logger?.warn(`secops/stall: 扣减 ${String(Math.round(-charged.amount / 1000))}s 时间信用（原地打转）`);
        }
        return { kind: 'enter', messages: [...decision.messages, userMessage(stallReminder(verdict))] };
    });
    return detector;
}
