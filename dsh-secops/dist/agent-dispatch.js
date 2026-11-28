/**
 * 方向级调度器：同方向多候选，按适配度选一个，坏了才换，该停就停。
 *
 * 三个判断，缺一个就会变成「一路跑到底」：
 *
 *   1. 派谁 —— 按目标形态算适配度，corvus 吃 MCP 启动命令、mcp-scan 吃配置文件，
 *      给错了就算跑起来也是白烧一次。适配度优先于固定优先级。
 *
 *   2. 何时换 —— 只有 agent 自身故障才自动换。工具坏了是机械替换，不需要判断；
 *      而「跑通了但没有定论」需要判断，交回主控决定，不自动烧第二个。
 *
 *   3. 何时停 —— 代价预算、同类故障熔断、形态不匹配、墙钟，四条独立的止损线。
 *      只靠 maxAttempts 计数是不够的：五次便宜的静态检查和一个会烧 LLM 额度的
 *      扫描器，在同一个计数器下平权，那等于用预算买噪音。
 */
import path from 'node:path';
import { detectTargetShape } from './agent-registry.js';
import { COST_WEIGHT, fitness } from './agent-registry.js';
export const DEFAULT_POLICY = {
    maxAttempts: 2,
    deadlineMs: 5 * 60 * 1000,
    costBudget: 10,
    // 默认停手：跑通但没定论时不再自动烧第二个。
    // 库默认与工程配置必须一致——两边不一致时，测试通过而线上白烧钱，最难查。
    stopOnInconclusive: true,
    faultCircuit: 2,
};
const DEFAULT_TIMEOUT_MS = 120_000;
function safeSegment(s) {
    return s.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40);
}
/**
 * 把候选的命令前缀、目标、以及候选自己声明的固定参数拼成 argv。
 *
 * 只做数组拼接，永远不拼字符串——一旦拼字符串就会出现参数注入：
 * 目标里带个空格或分号就能变成另一个参数或第二条命令。
 */
export function buildArgv(candidate, target, attemptIndex, options) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // 每次尝试独立目录：上一次的残留报告绝不能被下一次的 verdict 读到，
    // 否则"上一轮扫出了发现"会被误记成本轮结论。
    const taskId = `${safeSegment(candidate.direction)}-${safeSegment(candidate.id)}-${attemptIndex}-${Date.now().toString(36)}`;
    const evidenceDir = path.join(options.evidenceRoot, taskId);
    const prefix = candidate.command ?? [];
    if (candidate.invocation === undefined) {
        return { argv: prefix, timeoutMs, supported: false, taskId, evidenceDir };
    }
    return {
        argv: [...prefix, ...candidate.invocation(target, { evidenceDir })],
        timeoutMs,
        supported: true,
        taskId,
        evidenceDir,
    };
}
/** 把失败原因归一成类别，用来判断「再试一个是不是白试」。 */
export function classifyFault(reason) {
    const r = reason.toLowerCase();
    if (r.includes('not found') || r.includes('enoent'))
        return 'missing-binary';
    if (r.includes('timed out') || r.includes('timeout'))
        return 'timeout';
    if (r.includes('terminated by signal'))
        return 'signal';
    if (r.includes('eacces') || r.includes('not executable'))
        return 'permission';
    if (r.includes('spawn error'))
        return 'spawn';
    if (r.startsWith('exit '))
        return 'nonzero-exit';
    if (r.includes('threw'))
        return 'executor-error';
    return 'other';
}
export class DirectionalDispatcher {
    registry;
    attempt;
    logger;
    evidenceRoot;
    supportsClaim;
    creditOf;
    policy;
    detectShape;
    constructor(options) {
        this.registry = options.registry;
        this.creditOf = options.creditOf;
        this.attempt = options.attempt;
        this.logger = options.logger;
        this.evidenceRoot = options.evidenceRoot;
        this.supportsClaim = options.supportsClaim ?? false;
        this.detectShape = options.detectShape ?? detectTargetShape;
        this.policy = {
            ...DEFAULT_POLICY,
            ...(options.maxAttempts === undefined ? {} : { maxAttempts: options.maxAttempts }),
            ...(options.policy ?? {}),
        };
    }
    async dispatch(request, signal) {
        const shape = this.detectShape(request.target);
        const policy = {
            ...this.policy,
            ...(request.maxAttempts === undefined ? {} : { maxAttempts: request.maxAttempts }),
            ...(request.secondOpinion === true ? { stopOnInconclusive: false, costBudget: this.policy.costBudget * 2 } : {}),
            ...(request.deadlineMs === undefined ? {} : { deadlineMs: request.deadlineMs }),
        };
        const deadline = Date.now() + policy.deadlineMs;
        const attempts = [];
        const tried = new Set();
        const faultCounts = new Map();
        let costSpent = 0;
        let lastReason;
        const finish = (stopReason, extra = {}) => ({
            settled: false,
            found: false,
            attempts,
            shape,
            costSpent,
            stopReason,
            claimLinked: this.claimLinkedFor(request),
            ...this.untriedOf(request.direction, shape, tried),
            ...(lastReason === undefined ? {} : { failureReason: lastReason }),
            ...extra,
        });
        for (;;) {
            if (signal.aborted)
                return finish('aborted');
            if (Date.now() > deadline) {
                this.logger?.warn(`dispatch: deadline reached after ${attempts.length} attempt(s)`);
                return finish('deadline');
            }
            if (attempts.length >= policy.maxAttempts)
                return finish('max-attempts');
            const pool = this.registry
                .available(request.direction, shape, this.creditOf === undefined ? {} : { creditOf: this.creditOf })
                .filter((c) => !tried.has(c.id));
            if (pool.length === 0)
                return finish('exhausted');
            // 形态全不匹配就不要再跑：这些 agent 明确声明吃不下这类输入，
            // 派出去的结果一定是失败，只是把时间花在证明一件已知的事上。
            if (pool.every((c) => fitness(c, shape) === 0)) {
                this.logger?.warn(`dispatch: no candidate accepts target shape "${shape}" in ${request.direction}`);
                return finish('no-fit');
            }
            // 太尉指定了首选就照办，但只在它真的能吃这个形态时才照办——
            // 分配信息不该覆盖适配度判断，那是两件事。
            const preferred = request.preferAgentId === undefined
                ? undefined
                : pool.find((c) => c.id === request.preferAgentId && fitness(c, shape) > 0);
            const candidate = preferred ?? pool.find((c) => fitness(c, shape) > 0) ?? pool[0];
            const fit = fitness(candidate, shape);
            const cost = candidate.cost ?? 'moderate';
            const weight = COST_WEIGHT[cost];
            if (costSpent + weight > policy.costBudget) {
                this.logger?.warn(`dispatch: cost budget exhausted (${costSpent}+${weight} > ${policy.costBudget}); not running ${candidate.id}`);
                return finish('cost-budget');
            }
            tried.add(candidate.id);
            costSpent += weight;
            const timeoutMs = request.timeoutMs ?? candidate.defaultTimeoutMs;
            const arg = buildArgv(candidate, request.target, attempts.length, {
                evidenceRoot: this.evidenceRoot,
                ...(timeoutMs === undefined ? {} : { timeoutMs }),
            });
            this.logger?.info(`dispatch: ${request.direction}/${shape} → ${candidate.id} (fitness=${fit}, cost=${cost}${arg.supported ? '' : ', unsupported'})`);
            let result;
            if (!arg.supported) {
                result = { kind: 'refused', reason: 'execution layer does not drive this agent kind' };
            }
            else {
                try {
                    result = await this.attempt(candidate, arg, signal, {
                        ...(request.claimId === undefined ? {} : { claimId: request.claimId }),
                        shape,
                    });
                }
                catch (err) {
                    result = { kind: 'agent-failure', reason: `attempt threw: ${err.message}` };
                }
            }
            attempts.push({
                agentId: candidate.id,
                direction: request.direction,
                result: result.kind,
                ...(result.kind === 'completed'
                    ? result.detail === undefined
                        ? {}
                        : { detail: result.detail }
                    : { reason: result.reason }),
                ...(candidate.kind === 'cli' && arg.supported ? { argv: arg.argv } : {}),
                evidenceDir: arg.evidenceDir,
                fitness: fit,
                cost,
            });
            switch (result.kind) {
                case 'completed':
                    this.registry.reportSuccess(candidate.id);
                    return {
                        by: candidate.id,
                        settled: true,
                        found: result.found,
                        ...(result.findingClass === undefined ? {} : { findingClass: result.findingClass }),
                        attempts,
                        shape,
                        costSpent,
                        stopReason: 'settled',
                        claimLinked: this.claimLinkedFor(request),
                        ...(result.detail === undefined ? {} : { detail: result.detail }),
                        ...this.untriedOf(request.direction, shape, tried),
                    };
                case 'agent-failure': {
                    this.registry.reportFailure(candidate.id);
                    lastReason = result.reason;
                    const fault = classifyFault(result.reason);
                    const seen = (faultCounts.get(fault) ?? 0) + 1;
                    faultCounts.set(fault, seen);
                    if (seen >= policy.faultCircuit) {
                        // 同一类故障重复出现，说明问题不在 agent 而在更外层（目标、网络、环境）。
                        // 继续换只是把同一个失败重演一遍。
                        this.logger?.warn(`dispatch: circuit open on "${fault}" (${seen} consecutive) — stopping`);
                        return finish('fault-circuit');
                    }
                    break;
                }
                case 'refused':
                    lastReason = result.reason;
                    break;
                case 'inconclusive':
                    lastReason = result.reason;
                    if (policy.stopOnInconclusive) {
                        // 跑通了但没定论：这不是 agent 的错，是信息不足。
                        // 继续换等于用第二个工具的偶然差异赌一个结论，交回主控更诚实。
                        return finish('inconclusive');
                    }
                    break;
            }
        }
    }
    claimLinkedFor(request) {
        return request.claimId !== undefined && this.supportsClaim;
    }
    untriedOf(direction, shape, tried) {
        const rest = this.registry
            .available(direction, shape, this.creditOf === undefined ? {} : { creditOf: this.creditOf })
            .filter((c) => !tried.has(c.id))
            .map((c) => ({ agent: c.id, fitness: fitness(c, shape) }));
        // 全部试完时不返回这个字段，避免在成功结果里塞一个空数组噪音
        return rest.length === 0 ? {} : { untried: rest };
    }
}
/**
 * 把进程现象翻译成 AttemptResult。
 *
 * 判定依据只有执行层能拿到的事实：退出码、是否超时、stderr 特征、
 * 以及 agent 约定的输出结构。绝不能靠猜——"输出里没出现 'vulnerable' 字样"
 * 不构成 no-finding 证据。
 */
/**
 * 环境不满足的特征串。
 *
 * 只认**机器可读的错误码**，不认自然语言措辞——「error」「failed」这类
 * 词在任何工具里都出现，拿它们判拒绝会把真正的失败说成环境问题。
 * 这里的每个码都被具体工具真正输出过（rea 的 provider_unavailable /
 * unsupported_version 来自 ghidra 12.2 与 rea 要求的 12.1.x 不匹配）。
 */
const ENV_UNFIT = [
    { re: /\bprovider_unavailable\b/, label: 'analysis provider unavailable' },
    { re: /\bunsupported_version\b/, label: 'engine version unsupported' },
    { re: /\bmissing_analysis_engine\b|\bengine_not_found\b/, label: 'analysis engine missing' },
    { re: /\bnot_configured\b/, label: 'required dependency not configured' },
];
/** 返回拒绝原因；没命中返回 undefined。 */
export function detectEnvUnfit(stdout, stderr) {
    const text = `${stdout ?? ''}\n${stderr}`;
    for (const { re, label } of ENV_UNFIT) {
        const m = re.exec(text);
        if (m === null)
            continue;
        // 抓命中行，让 reason 能被人直接核对，而不是只给一个标签。
        const line = text
            .split('\n')
            .find((l) => re.test(l))
            ?.trim()
            .slice(0, 160);
        return `refused: ${label}${line === undefined || line === '' ? '' : ` — ${line}`}`;
    }
    return undefined;
}
export function classifyProcess(input) {
    if (input.spawnError !== undefined) {
        const code = input.spawnError.code;
        if (code === 'ENOENT') {
            return { kind: 'agent-failure', reason: 'executable not found (ENOENT)' };
        }
        if (code === 'EACCES') {
            return { kind: 'agent-failure', reason: 'executable not executable (EACCES)' };
        }
        return { kind: 'agent-failure', reason: `spawn error: ${code ?? input.spawnError.message}` };
    }
    if (input.timedOut) {
        return { kind: 'agent-failure', reason: 'timed out' };
    }
    // 崩溃类信号在 POSIX 下体现为 null exitCode
    if (input.exitCode === null) {
        return { kind: 'agent-failure', reason: 'terminated by signal' };
    }
    if (input.structured !== undefined) {
        return {
            kind: 'completed',
            found: input.structured.found,
            ...(input.structured.class === undefined ? {} : { findingClass: input.structured.class }),
        };
    }
    // 跑起来了、但不是因为目标而是因为**本机环境不满足**而拒绝干活。
    // 这类失败重试和换目标都不会变，而且不是 agent 的过错——把它计进
    // agent-failure 会让误报账记错人，还会在熔断计数里堆出假信号。
    // 典型：rea 装了但 Ghidra 版本不兼容，报 provider_unavailable / unsupported_version。
    const unfit = detectEnvUnfit(input.stdout, input.stderr);
    if (unfit !== undefined)
        return { kind: 'refused', reason: unfit };
    if (input.exitCode === 0) {
        // 退出码 0 但没有结构化输出：跑通了，结论不明。
        // 这里最容易被写错成 found=true 或 found=false，两者都是编造。
        return { kind: 'inconclusive', reason: 'exit 0 without structured verdict' };
    }
    if (input.exitCode === 2 || /usage:|unknown (option|argument)|invalid argument/i.test(input.stderr)) {
        return { kind: 'refused', reason: `agent rejected invocation (exit ${input.exitCode})` };
    }
    return {
        kind: 'agent-failure',
        reason: `exit ${input.exitCode}${input.stderr.trim() === '' ? '' : `: ${firstLine(input.stderr)}`}`,
    };
}
function firstLine(s) {
    return (s.trim().split('\n')[0] ?? '').slice(0, 200);
}
