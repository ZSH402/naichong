/**
 * 配置解析与校验。
 *
 * 不引入 schemastery：这个插件的配置面很小，手写校验能让失败信息直接指向出错字段，
 * 也少一层依赖。所有值都在加载期校验，不留到运行期才发现。
 */
function assertPositiveInt(value, field) {
    if (value === undefined)
        return undefined;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
        throw new TypeError(`secops: config field "${field}" must be a positive safe integer, got ${String(value)}`);
    }
    return value;
}
/** 非负有限数（允许 0）。权重类字段用它，别用 assertPositiveInt 把 0 挡住。 */
function assertNonNegative(value, field) {
    if (value === undefined)
        return undefined;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new TypeError(`secops: config field "${field}" must be a non-negative finite number, got ${String(value)}`);
    }
    return value;
}
export function resolveConfig(config) {
    if (config !== undefined && (typeof config !== 'object' || config === null)) {
        throw new TypeError('secops: config must be an object when present');
    }
    const input = config ?? {};
    const rawHosts = input.allowedHosts;
    if (rawHosts !== undefined && !Array.isArray(rawHosts)) {
        throw new TypeError('secops: config field "allowedHosts" must be an array of strings');
    }
    const allowedHosts = (rawHosts ?? []).map((host) => {
        if (typeof host !== 'string' || host.trim().length === 0) {
            throw new TypeError('secops: config field "allowedHosts" must contain non-empty strings');
        }
        return host.trim().toLowerCase();
    });
    const rawMode = input.scopeMode;
    if (rawMode !== undefined && rawMode !== 'enforce' && rawMode !== 'open') {
        throw new TypeError('secops: config field "scopeMode" must be "enforce" or "open"');
    }
    const scopeMode = rawMode ?? 'enforce';
    const logDecisions = input.logDecisions;
    if (logDecisions !== undefined && typeof logDecisions !== 'boolean') {
        throw new TypeError('secops: config field "logDecisions" must be a boolean');
    }
    const q = input.queue ?? {};
    const baseDir = process.cwd();
    return {
        allowedHosts: Object.freeze([...new Set(allowedHosts)]),
        scopeMode,
        maxToolCalls: assertPositiveInt(input.maxToolCalls, 'maxToolCalls'),
        maxWallClockMs: assertPositiveInt(input.maxWallClockMs, 'maxWallClockMs'),
        maxSteps: assertPositiveInt(input.maxSteps, 'maxSteps'),
        logDecisions: logDecisions ?? true,
        deniedTools: Object.freeze((input.deniedTools ?? []).filter((t) => typeof t === 'string' && t.length > 0)),
        hitl: {
            enabled: input.hitl?.enabled ?? false,
            allowlist: Object.freeze([...(input.hitl?.allowlist ?? [])]),
            requireApproval: Object.freeze([...(input.hitl?.requireApproval ?? ['write', 'destructive', 'c2'])]),
        },
        fallback: {
            routes: Object.freeze((input.fallback?.routes ?? [])
                .filter((r) => typeof r?.provider === 'string' && r.provider.length > 0 && typeof r?.model === 'string' && r.model.length > 0)
                .map((r) => Object.freeze({ provider: r.provider, model: r.model }))),
            maxSwitches: Math.max(0, input.fallback?.maxSwitches ?? 3),
        },
        provenance: {
            enabled: input.provenance?.enabled ?? true,
            strict: input.provenance?.strict ?? true,
            store: input.provenance?.store,
        },
        egress: {
            enabled: input.egress?.enabled ?? false,
            socketPath: input.egress?.socketPath ?? `${baseDir}/.dsh-secops/egress.sock`,
        },
        queue: {
            enabled: q.enabled ?? false,
            file: q.file ?? `${baseDir}/.dsh-secops/queue.jsonl`,
            evidenceRoot: q.evidenceRoot ?? `${baseDir}/.dsh-secops/evidence`,
            concurrency: Math.max(1, q.concurrency ?? 2),
            timeoutMs: Math.max(1, q.timeoutMs ?? 120_000),
            requeueInterrupted: q.requeueInterrupted ?? false,
        },
        agentDispatch: {
            // 默认跟随 queue：agent 调度复用队列的执行器和证据目录，
            // 队列不开就无处落证据，这时开着调度只会产出没有证据的结论。
            enabled: input.agentDispatch?.enabled ?? (q.enabled ?? false),
            maxAttempts: assertPositiveInt(input.agentDispatch?.maxAttempts, 'agentDispatch.maxAttempts') ?? 2,
            overallTimeoutMs: assertPositiveInt(input.agentDispatch?.overallTimeoutMs, 'agentDispatch.overallTimeoutMs') ?? 300_000,
            costBudget: assertPositiveInt(input.agentDispatch?.costBudget, 'agentDispatch.costBudget') ?? 10,
            stopOnInconclusive: input.agentDispatch?.stopOnInconclusive ?? true,
            faultCircuit: assertPositiveInt(input.agentDispatch?.faultCircuit, 'agentDispatch.faultCircuit') ?? 2,
        },
        timeCredit: {
            enabled: input.timeCredit?.enabled ?? false,
            baseMs: assertPositiveInt(input.timeCredit?.baseMs, 'timeCredit.baseMs') ?? 30 * 60 * 1000,
            grantMs: assertPositiveInt(input.timeCredit?.grantMs, 'timeCredit.grantMs') ?? 10 * 60 * 1000,
            maxMs: assertPositiveInt(input.timeCredit?.maxMs, 'timeCredit.maxMs') ?? 120 * 60 * 1000,
            grantCooldownMs: assertPositiveInt(input.timeCredit?.grantCooldownMs, 'timeCredit.grantCooldownMs') ?? 2 * 60 * 1000,
            warnAtMs: assertPositiveInt(input.timeCredit?.warnAtMs, 'timeCredit.warnAtMs') ?? 5 * 60 * 1000,
            debitMs: assertPositiveInt(input.timeCredit?.debitMs, 'timeCredit.debitMs') ?? 5 * 60 * 1000,
            maxDebitMs: assertNonNegative(input.timeCredit?.maxDebitMs, 'timeCredit.maxDebitMs') ?? 15 * 60 * 1000,
            debitCooldownMs: assertPositiveInt(input.timeCredit?.debitCooldownMs, 'timeCredit.debitCooldownMs') ?? 5 * 60 * 1000,
        },
        mcp: {
            enabled: input.mcp?.enabled ?? false,
            command: Object.freeze((input.mcp?.command ?? []).filter((c) => typeof c === 'string' && c.length > 0)),
            cwd: input.mcp?.cwd,
            timeoutMs: assertPositiveInt(input.mcp?.timeoutMs, 'mcp.timeoutMs') ?? 30_000,
        },
        artex: {
            enabled: input.artex?.enabled ?? false,
            baseUrl: (input.artex?.baseUrl ?? 'http://127.0.0.1:8787').replace(/\/+$/, ''),
            password: input.artex?.password ?? '',
        },
        council: {
            enabled: input.council?.enabled ?? (q.enabled ?? false),
            credit: {
                enabled: input.council?.credit?.enabled ?? true,
                // 0.15 是实测量级：总执行 100 次时，没跑过的牌拿 +0.32 的探索分，
                // 刚好让它排在「成功过几次」后面、排在「失手过」前面。设更大（0.5）
                // 会让没跑过的牌永远盖住已验证的好牌；设 0 则早熟，一旦某牌领先就再不换人。
                exploreWeight: assertNonNegative(input.council?.credit?.exploreWeight, 'council.credit.exploreWeight') ?? 0.15,
                // 90 天：一次渗透周期内基本不衰减，跨季度开始淡出。
                halfLifeMs: assertNonNegative(input.council?.credit?.halfLifeMs, 'council.credit.halfLifeMs') ?? 90 * 24 * 60 * 60 * 1000,
            },
            rateWindowMs: assertPositiveInt(input.council?.rateWindowMs, 'council.rateWindowMs') ?? 60_000,
            rateMaxPerWindow: assertPositiveInt(input.council?.rateMaxPerWindow, 'council.rateMaxPerWindow') ?? 6,
            breakerThreshold: assertPositiveInt(input.council?.breakerThreshold, 'council.breakerThreshold') ?? 3,
            breakerCooldownMs: assertPositiveInt(input.council?.breakerCooldownMs, 'council.breakerCooldownMs') ?? 120_000,
            allowedHosts: Object.freeze((input.council?.allowedHosts ?? []).filter((h) => typeof h === 'string' && h.length > 0)),
        },
    };
}
