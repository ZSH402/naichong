/**
 * 方向级调度的模型侧工具。
 *
 * 两个工具就够了：
 *   agent_directions —— 看每个方向有哪些 agent、谁健康、谁缺依赖
 *   agent_dispatch   —— 给方向和目标，系统自己挑 agent、失败自动换下一个
 *
 * 刻意不暴露「指定用哪个 agent」的参数：那会把「一个不行换下一个」的决策
 * 交回给模型，而模型没有失败率数据，凭一次失败就换人且不会记得换回来。
 */
import fs from 'node:fs';
import path from 'node:path';
import { classifyProcess } from './agent-dispatch.js';
const MAX_VERDICT_BYTES = 32 * 1024 * 1024;
const DIRECTIONS_SCHEMA = {
    type: 'object',
    properties: {
        directions: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    direction: { type: 'string' },
                    total: { type: 'number' },
                    ready: { type: 'number' },
                    agents: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                id: { type: 'string' },
                                kind: { type: 'string' },
                                capability: { type: 'string' },
                                priority: { type: 'number' },
                                failures: { type: 'number' },
                                cooling: { type: 'boolean' },
                                unavailable: { type: 'boolean' },
                                verdict_capable: { type: 'boolean', description: 'Can produce a terminal found/clean verdict.' },
                                missing_env: { type: 'array', items: { type: 'string' }, description: 'Required environment variables that are not set.' },
                                requires: { type: 'string' },
                            },
                            required: ['id', 'kind', 'capability'],
                        },
                    },
                },
                required: ['direction', 'total', 'ready'],
            },
        },
    },
    required: ['directions'],
};
const DISPATCH_SCHEMA = {
    type: 'object',
    properties: {
        settled: { type: 'boolean', description: 'A terminal verdict was reached.' },
        found: { type: 'boolean', description: 'The terminal verdict reports findings.' },
        by: { type: 'string', description: 'Which agent produced the terminal verdict.' },
        detail: { type: 'string' },
        failure_reason: { type: 'string' },
        stop_reason: {
            type: 'string',
            description: 'Why no further agent was tried: settled | exhausted | no-fit | cost-budget | deadline | fault-circuit | inconclusive | max-attempts | aborted',
        },
        shape: { type: 'string', description: 'Detected target shape, used to pick the agent.' },
        cost_spent: { type: 'number', description: 'Accumulated cost weight (cheap=1, moderate=3, expensive=10).' },
        untried: {
            type: 'array',
            items: {
                type: 'object',
                properties: { agent: { type: 'string' }, fitness: { type: 'number' } },
                required: ['agent', 'fitness'],
            },
            description: 'Candidates left untried when stopping, with their fitness for this target shape.',
        },
        claim_linked: { type: 'boolean', description: 'A claim_id was provided AND the execution layer really linked evidence.' },
        claim_note: { type: 'string', description: 'Set when claim_id was given but evidence linking did not happen.' },
        attempts: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    agent: { type: 'string' },
                    result: { type: 'string', description: 'completed | agent-failure | inconclusive | refused' },
                    fitness: { type: 'number', description: 'How well this agent matched the target shape (1 exact, 0.5 open, 0 refused).' },
                    cost: { type: 'string' },
                    reason: { type: 'string' },
                    detail: { type: 'string' },
                    evidence_dir: { type: 'string' },
                },
                required: ['agent', 'result'],
            },
        },
    },
    required: ['settled', 'found'],
};
/**
 * 副 agent 的凭据。
 *
 * 存 `$DSH_HOME/credentials.json`（600），结构 `{ "agents": { "<id>": { "KEY": "value" } } }`。
 *
 * 为什么单独一个文件而不是写进候选定义：候选是编译期常量，key 是运行时秘密，
 * 两者混在一起意味着「改 key 要重新构建」。而且这个文件同时被 UI 的只读端点读取，
 * 一份文件比「配置里有、环境变量里有、UI 里又有一份」可靠。
 *
 * 读失败一律当没有：缺 key 的后果是那个 agent 被判不可用（requiresEnv 不满足），
 * 这是一个明确的、可解释的状态，比启动时崩掉好。
 */
export function readAgentCredentials(agentId, home) {
    const base = home ?? process.env.DSH_HOME;
    if (base === undefined || base === '')
        return undefined;
    const file = path.join(base, 'credentials.json');
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    catch {
        return undefined;
    }
    const agents = parsed.agents;
    if (agents === null || typeof agents !== 'object')
        return undefined;
    const entry = agents[agentId];
    if (entry === null || typeof entry !== 'object')
        return undefined;
    const out = {};
    for (const [k, v] of Object.entries(entry)) {
        if (typeof v === 'string' && v !== '')
            out[k] = v;
    }
    return Object.keys(out).length === 0 ? undefined : out;
}
/**
 * 把 QueueRunner 包成 dispatcher 的 attempt 函数。
 *
 * 关键点：任务 id 必须用 dispatcher 给的 taskId，因为 verbdict 解析器要按
 * 同一个目录找 agent 写的报告。两边各自算目录会出现"报告在 A、stdout 在 B"，
 * 然后 verdict 永远读不到文件，退化成 inconclusive。
 */
export function createQueueAttempt(runner, options = {}) {
    const cwd = options.cwd ?? process.cwd();
    return async (candidate, arg, signal, meta) => {
        fs.mkdirSync(arg.evidenceDir, { recursive: true });
        // 合并顺序：候选声明的静态依赖 → 用户凭据。凭据能覆盖，因为它是后改的。
        const credentials = readAgentCredentials(candidate.id);
        const effectiveEnv = candidate.env === undefined && credentials === undefined
            ? undefined
            : { ...(candidate.env ?? {}), ...(credentials ?? {}) };
        if (meta.claimId !== undefined) {
            options.link?.(arg.taskId, {
                claimId: meta.claimId,
                ...(meta.shape === undefined ? {} : { shape: meta.shape }),
            });
        }
        runner.submit({
            id: arg.taskId,
            kind: `agent:${candidate.id}`,
            argv: arg.argv,
            // ownWorkdir 的候选在自己的证据目录里跑：它们的产物路径是 cwd 相对的，
            // 放在共享目录会让并发派活互相覆盖。
            cwd: candidate.ownWorkdir === true ? arg.evidenceDir : cwd,
            timeoutMs: arg.timeoutMs,
            // 候选声明的依赖随任务走到执行层。靠 shell 里 export 是不可复现的：
            // 换一种启动方式（IDE、服务、CI）就悄悄退化，而且没有地方会报出来。
            // 用户从 UI 填的凭据覆盖候选自带的同名字段——UI 里的值是更近期的意图。
            ...(effectiveEnv === undefined ? {} : { env: effectiveEnv }),
        });
        const task = await runner.waitFor(arg.taskId, { signal });
        const metaJson = readMeta(arg.evidenceDir);
        const stdout = readCapped(path.join(arg.evidenceDir, 'stdout.log'));
        const stderr = readCapped(path.join(arg.evidenceDir, 'stderr.log'));
        const spawnErrorCode = typeof metaJson?.spawnErrorCode === 'string' ? metaJson.spawnErrorCode : undefined;
        const spawnError = spawnErrorCode === undefined
            ? metaJson?.spawnError !== undefined
                ? Object.assign(new Error(String(metaJson.spawnError)), { code: 'UNKNOWN' })
                : undefined
            : Object.assign(new Error(spawnErrorCode), { code: spawnErrorCode });
        // verdict 优先于退出码：promptfoo 在有用例失败时 exit 100，
        // 那是「测出问题」而不是「工具坏了」。先让解析器表态，它说不知道再看进程现象。
        const ctx = {
            stdout,
            stderr,
            exitCode: typeof metaJson?.exitCode === 'number' ? metaJson.exitCode : (task?.exitCode ?? null),
            evidenceDir: arg.evidenceDir,
        };
        let structured;
        if (candidate.verdict !== undefined) {
            try {
                structured = candidate.verdict(ctx);
            }
            catch (err) {
                options.logger?.warn(`agent ${candidate.id}: verdict parser threw: ${String(err)}`);
                structured = undefined;
            }
        }
        const classified = classifyProcess({
            exitCode: ctx.exitCode,
            timedOut: metaJson?.timedOut === true,
            stderr,
            ...(typeof ctx.stdout === 'string' ? { stdout: ctx.stdout } : {}),
            ...(spawnError === undefined ? {} : { spawnError }),
            ...(structured === undefined ? {} : { structured }),
        });
        // classifyProcess 只带 found；把 detail 补回终态
        if (classified.kind === 'completed') {
            return {
                kind: 'completed',
                found: classified.found,
                ...(structured?.detail === undefined ? {} : { detail: structured.detail }),
                ...(structured?.class === undefined ? {} : { findingClass: structured.class }),
            };
        }
        return classified;
    };
}
function readMeta(evidenceDir) {
    try {
        const raw = fs.readFileSync(path.join(evidenceDir, 'meta.json'), 'utf8');
        return JSON.parse(raw);
    }
    catch {
        return undefined;
    }
}
function readCapped(file) {
    try {
        const stat = fs.statSync(file);
        if (stat.size <= MAX_VERDICT_BYTES)
            return fs.readFileSync(file, 'utf8');
        // 超限只读尾部：结构化报告通常在最后，而全文读进内存会把进程拖死
        const fd = fs.openSync(file, 'r');
        try {
            const buf = Buffer.allocUnsafe(MAX_VERDICT_BYTES);
            fs.readSync(fd, buf, 0, MAX_VERDICT_BYTES, stat.size - MAX_VERDICT_BYTES);
            return buf.toString('utf8');
        }
        finally {
            fs.closeSync(fd);
        }
    }
    catch {
        return '';
    }
}
export function agentTools(dispatcher, registry, options = {}) {
    const overallTimeoutMs = options.overallTimeoutMs ?? 600_000;
    /**
     * 本轮真正可用的时间上限。
     *
     * 配置值当**下限**而不是上限：一个方向里可能同时有 84 秒的牌和 27 分钟的牌，
     * 拿一个固定数当上限，慢牌必然被砍在半路——实测 strix 完整跑一次 1645 秒，
     * 而这里的默认值是 600 秒，它从来没跑完过。
     *
     * 只按慢牌放大、不乘尝试次数：某个候选超时通常说明环境有问题，再拿第二张慢牌
     * 赌一次意义不大（那是 faultCircuit 的活）。
     */
    const budgetFor = (direction) => {
        const pool = registry.available(direction);
        let slowest = 0;
        for (const c of pool)
            slowest = Math.max(slowest, c.defaultTimeoutMs ?? 0);
        return Math.max(overallTimeoutMs, Math.round(slowest * 1.2) + 60_000);
    };
    const directions = {
        name: 'agent_directions',
        description: 'List every capability direction and the specialist agents registered under it, with health state. ' +
            'A direction with ready=0 has no usable agent right now — install the missing tool listed in `requires` ' +
            'instead of retrying, because retrying a missing binary never succeeds.',
        parameters: {
            type: 'object',
            properties: {
                direction: { type: 'string', description: 'Optional: restrict output to one direction.' },
            },
        },
        output: {
            schema: DIRECTIONS_SCHEMA,
            render: (_args, value) => [{ type: 'text', text: renderDirections(value) }],
        },
        async execute(args) {
            const only = typeof args.direction === 'string' ? args.direction : undefined;
            const summaries = registry.summary().filter((s) => only === undefined || s.direction === only);
            const out = summaries.map((s) => ({
                direction: s.direction,
                total: s.total,
                ready: s.ready,
                agents: registry.list(s.direction).map((a) => ({
                    id: a.id,
                    kind: a.kind,
                    capability: a.capability,
                    ...(a.priority === undefined ? {} : { priority: a.priority }),
                    failures: a.failures,
                    cooling: a.cooling,
                    unavailable: a.unavailable,
                    verdict_capable: a.verdictCapable,
                    ...(a.missingEnv === undefined ? {} : { missing_env: [...a.missingEnv] }),
                    ...(a.requires === undefined ? {} : { requires: a.requires }),
                })),
            }));
            return { directions: out };
        },
    };
    const dispatch = {
        name: 'agent_dispatch',
        description: 'Hand a task to the best available specialist agent for a direction. The system picks by priority, ' +
            'automatically falls over to the next agent when one fails to run, and reports the full attempt chain. ' +
            'Failover only happens on agent faults (missing binary, crash, timeout). A run that completes without ' +
            'a parsable verdict is reported as inconclusive rather than guessed as clean.',
        parameters: {
            type: 'object',
            properties: {
                direction: { type: 'string', description: 'Capability direction, e.g. "mcp-security".' },
                target: {
                    type: 'string',
                    description: 'What to test. Meaning depends on the direction: MCP server URL or launch command, a config file path, a source directory, a base URL.',
                },
                timeout_ms: { type: 'number', description: 'Per-agent timeout in milliseconds.' },
                max_attempts: { type: 'number', description: 'How many agents to try at most (default 5).' },
                claim_id: {
                    type: 'string',
                    description: 'Claim to attach the produced evidence to. Without it the run is just log output; with it the evidence ' +
                        'goes through the relevance and independent-path checks before it counts.',
                },
                second_opinion: {
                    type: 'boolean',
                    description: 'Only set when you deliberately want a second agent after a run that produced no verdict. ' +
                        'By default such a run stops there — burning a second agent on an unproven hunch is how budgets disappear.',
                },
            },
            required: ['direction', 'target'],
        },
        output: {
            schema: DISPATCH_SCHEMA,
            render: (_args, value) => [{ type: 'text', text: renderDispatch(value) }],
        },
        async execute(args) {
            const direction = String(args.direction);
            const target = String(args.target);
            const claim_id = typeof args.claim_id === 'string' ? args.claim_id : undefined;
            const budget = budgetFor(direction);
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), budget);
            try {
                const outcome = await dispatcher.dispatch({
                    direction: direction,
                    target,
                    ...(typeof args.timeout_ms === 'number' ? { timeoutMs: args.timeout_ms } : {}),
                    ...(typeof args.max_attempts === 'number' ? { maxAttempts: args.max_attempts } : {}),
                    ...(typeof args.claim_id === 'string' ? { claimId: args.claim_id } : {}),
                    ...(args.second_opinion === true ? { secondOpinion: true } : {}),
                    deadlineMs: budget,
                }, controller.signal);
                return {
                    settled: outcome.settled,
                    found: outcome.found,
                    ...(outcome.by === undefined ? {} : { by: outcome.by }),
                    ...(outcome.detail === undefined ? {} : { detail: outcome.detail }),
                    ...(outcome.failureReason === undefined ? {} : { failure_reason: outcome.failureReason }),
                    stop_reason: outcome.stopReason,
                    shape: outcome.shape,
                    cost_spent: outcome.costSpent,
                    ...(outcome.untried === undefined ? {} : { untried: outcome.untried }),
                    claim_linked: outcome.claimLinked,
                    ...(claim_id !== undefined && !outcome.claimLinked
                        ? { claim_note: 'claim_id was provided but this execution layer did not link the run to the claim — treat the result as log-only' }
                        : {}),
                    attempts: outcome.attempts.map((a) => ({
                        agent: a.agentId,
                        result: a.result,
                        fitness: a.fitness,
                        cost: a.cost,
                        ...(a.reason === undefined ? {} : { reason: a.reason }),
                        ...(a.detail === undefined ? {} : { detail: a.detail }),
                        evidence_dir: a.evidenceDir,
                    })),
                };
            }
            finally {
                clearTimeout(timer);
            }
        },
    };
    return [directions, dispatch];
}
export function installAgentTools(ctx, dispatcher, registry, options = {}) {
    for (const tool of agentTools(dispatcher, registry, options)) {
        ctx.tools.register(tool);
    }
}
function renderDirections(result) {
    const list = (result.directions ?? []);
    if (list.length === 0)
        return 'No directions registered.';
    const lines = [];
    for (const d of list) {
        lines.push(`${String(d.direction)} — ${String(d.ready)}/${String(d.total)} ready`);
        for (const a of (d.agents ?? [])) {
            const marks = [
                a.unavailable === true ? (a.missingEnv === undefined ? 'MISSING' : 'NO-CREDENTIAL') : undefined,
                a.cooling === true ? 'COOLING' : undefined,
                a.verdict_capable === false ? 'NO-VERDICT' : undefined,
                typeof a.failures === 'number' && a.failures > 0 ? `failures=${String(a.failures)}` : undefined,
            ].filter((m) => m !== undefined);
            lines.push(`  ${String(a.id)} [${String(a.kind)}]${marks.length === 0 ? '' : ` (${marks.join(', ')})`} — ${String(a.capability)}` +
                (typeof a.requires === 'string' ? `\n    requires: ${a.requires}` : ''));
        }
    }
    return lines.join('\n');
}
/**
 * 派活结果的渲染文本。
 *
 * 用 `key=value` 而不是自然语言：上一版写成 "settled by rabin2 — found=false"，
 * 模型把 "settled by X" 读成 settled=X，字段直接错位。渲染格式本身就是接口，
 * 让人读着顺的句式恰恰是模型最容易解析错的句式。
 */
export function renderDispatch(result) {
    const attempts = (result.attempts ?? []);
    const lines = [
        `settled=${String(result.settled)}`,
        `found=${String(result.found)}`,
        `by=${typeof result.by === 'string' ? result.by : 'none'}`,
        `claim_linked=${String(result.claim_linked === true)}`,
        `stop_reason=${String(result.stop_reason)}`,
        `shape=${String(result.shape)}`,
        `cost_spent=${String(result.cost_spent)}`,
    ];
    if (typeof result.claim_note === 'string')
        lines.push(`claim_note=${result.claim_note}`);
    if (typeof result.detail === 'string')
        lines.push(`detail=${result.detail}`);
    if (typeof result.failure_reason === 'string')
        lines.push(`failure_reason=${result.failure_reason}`);
    const untried = (result.untried ?? []);
    if (untried.length > 0) {
        lines.push(`untried: ${untried.map((u) => `${String(u.agent)}(fitness=${String(u.fitness)})`).join(', ')}`);
    }
    if (attempts.length > 0) {
        lines.push('attempts:');
        for (const a of attempts) {
            const extras = [
                typeof a.detail === 'string' ? `detail=${a.detail}` : undefined,
                typeof a.reason === 'string' ? `reason=${a.reason}` : undefined,
                typeof a.evidence_dir === 'string' ? `evidence=${a.evidence_dir}` : undefined,
            ].filter((x) => x !== undefined);
            lines.push(`  ${String(a.agent)} result=${String(a.result)} fitness=${String(a.fitness)} cost=${String(a.cost)}` +
                (extras.length === 0 ? '' : ' ' + extras.join(' ')));
        }
    }
    return lines.join('\n');
}
