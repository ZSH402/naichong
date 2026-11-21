/**
 * 方向级 Agent 注册表：同一能力方向放多个候选，失败自动换下一个。
 *
 * 项目哲学是「一个方向的 agent 完成不了，就换下一个」。这条不能靠人记，
 * 要由系统执行——同一个方向注册若干候选，按优先级尝试，失败降级。
 *
 * 与 Model Fallback 同构，但对象不同：
 *   Model Fallback：provider 失败 → 换 provider（同一件事换个后端）
 *   Agent Registry：agent 失败 → 换 agent（同一方向换个做法）
 *
 * 健康状态是**进程内**的：重启后所有 agent 重新视为健康。外部工具的失败
 * 常常是环境瞬态（网络、临时限流），跨进程记忆会把偶发失败固化成永久拉黑。
 * 而「没装」是持久事实，由 probe 单独处理，不混进失败计数。
 */
import fs from 'node:fs';
import path from 'node:path';
export const COST_WEIGHT = { cheap: 1, moderate: 3, expensive: 10 };
const DEFAULT_THRESHOLD = 2;
const DEFAULT_COOLDOWN_MS = 5 * 60 * 1000;
export class AgentRegistry {
    byDirection = new Map();
    byId = new Map();
    now;
    constructor(candidates, options = {}) {
        this.now = options.now ?? Date.now;
        for (const c of candidates) {
            if (this.byId.has(c.id))
                throw new Error(`agent-registry: duplicate agent id "${c.id}"`);
            const internal = { candidate: c, failures: 0, cooldownUntil: 0, unavailable: false };
            this.byId.set(c.id, internal);
            const list = this.byDirection.get(c.direction) ?? [];
            list.push(internal);
            list.sort((a, b) => (a.candidate.priority ?? 100) - (b.candidate.priority ?? 100));
            this.byDirection.set(c.direction, list);
        }
    }
    blocked(internal) {
        return internal.unavailable || internal.cooldownUntil > this.now();
    }
    stateOf(i) {
        const until = i.cooldownUntil > this.now() ? i.cooldownUntil : undefined;
        return {
            id: i.candidate.id,
            direction: i.candidate.direction,
            kind: i.candidate.kind,
            capability: i.candidate.capability,
            ...(i.candidate.priority === undefined ? {} : { priority: i.candidate.priority }),
            failures: i.failures,
            cooling: until !== undefined,
            unavailable: i.unavailable,
            verdictCapable: i.candidate.verdict !== undefined,
            ...(until === undefined ? {} : { cooldownUntil: until }),
            ...(i.candidate.requires === undefined ? {} : { requires: i.candidate.requires }),
            ...(() => {
                const lacking = (i.candidate.requiresEnv ?? []).filter((group) => !group.some((k) => hasEnv(k, i.candidate.id)));
                return lacking.length === 0 ? {} : { missingEnv: lacking.map((g) => g.join('|')) };
            })(),
        };
    }
    /** 某方向下所有候选的当前状态，按优先级排序。 */
    list(direction) {
        return (this.byDirection.get(direction) ?? []).map((i) => this.stateOf(i));
    }
    /**
     * 为该方向挑一个可用 agent。
     *
     * 跳过探测失败的与冷却中的；若全部不可用则返回 undefined——宁可让调度器
     * 明确报「该方向无可用 agent」，也不要挑一个已知装不上的去跑一遍拿假失败。
     */
    select(direction) {
        const list = this.byDirection.get(direction) ?? [];
        return list.find((i) => !this.blocked(i))?.candidate;
    }
    /**
     * 该方向当前可用、且明确能吃这个形态的候选。
     *
     * 与 available 的区别：available 只排序不过滤，fitness=0 的仍在列表里
     * （调度器要自己判 no-fit）；accepting 直接排除——分析层问「谁能干这活」时，
     * 不该拿到一个明确干不了的人。
     */
    accepting(direction, shape) {
        return this.available(direction, shape).filter((c) => fitness(c, shape) > 0);
    }
    /**
     * 该方向当前全部可用候选。
     *
     * 给了 shape 就按「适配度优先、优先级次之」排序；不给则维持优先级顺序。
     * 适配度优先是关键：corvus 优先级更高，但目标是一份配置文件时它根本吃不下，
     * 硬按优先级派出去只会白烧一次。
     */
    available(direction, shape, options = {}) {
        const list = (this.byDirection.get(direction) ?? []).filter((i) => !this.blocked(i)).map((i) => i.candidate);
        if (shape === undefined)
            return list;
        return list
            .map((c) => ({ c, f: fitness(c, shape), p: effectivePriorityOf(c, shape, options.creditOf) }))
            .sort((a, b) => b.f - a.f || a.p - b.p)
            .map((x) => x.c);
    }
    /** 上报一次失败。达到阈值进入冷却。 */
    reportFailure(id) {
        const i = this.byId.get(id);
        if (i === undefined)
            return;
        i.failures += 1;
        const threshold = i.candidate.failureThreshold ?? DEFAULT_THRESHOLD;
        if (i.failures >= threshold) {
            i.cooldownUntil = this.now() + (i.candidate.cooldownMs ?? DEFAULT_COOLDOWN_MS);
        }
    }
    /** 上报一次成功。清零失败计数并解除冷却。 */
    reportSuccess(id) {
        const i = this.byId.get(id);
        if (i === undefined)
            return;
        i.failures = 0;
        i.cooldownUntil = 0;
    }
    /** 标记命令不存在。这是持久事实，不参与冷却恢复。 */
    markUnavailable(id) {
        const i = this.byId.get(id);
        if (i !== undefined)
            i.unavailable = true;
    }
    markAvailable(id) {
        const i = this.byId.get(id);
        if (i !== undefined)
            i.unavailable = false;
    }
    summary() {
        return [...this.byDirection.entries()].map(([direction, list]) => ({
            direction,
            total: list.length,
            ready: list.filter((i) => !this.blocked(i)).length,
        }));
    }
    get(id) {
        return this.byId.get(id)?.candidate;
    }
    all() {
        return [...this.byId.values()].map((i) => i.candidate);
    }
}
/** 信誉中性值。与 council/credit.ts 的 CREDIT_NEUTRAL 必须一致（wiring 有断言）。 */
const CREDIT_NEUTRAL = 0.5;
/**
 * 有效优先级 = 作者优先级 × (中性 / 信誉)。
 *
 * 用乘性修正而不是直接拿信誉当排序键：中性牌优先级不变，信誉高的提前，
 * 信誉低的后退，但作者用 priority 表达过的量级关系（快牌先于慢牌）依然有效。
 * 直接按信誉绝对值排会把「快而略糙」和「慢而准」压成同一个维度。
 */
function effectivePriorityOf(candidate, shape, creditOf) {
    const priority = candidate.priority ?? 100;
    const credit = creditOf?.(candidate.id, shape);
    if (credit === undefined || credit <= 0)
        return priority;
    return priority * (CREDIT_NEUTRAL / credit);
}
/**
 * 这个环境变量有没有值 —— 进程环境或用户凭据文件，任一即可。
 *
 * 两处都要看：用户从 UI 填的 key 落在 credentials.json 里，而探测只看
 * process.env 的话，面板显示「已配置」、探测还说「缺 key」，同一个事实两个答案。
 * 注入侧（agent-tools）和探测侧必须用同一套来源，否则「不可用」的判断会骗人。
 */
function hasEnv(key, agentId) {
    if ((process.env[key] ?? '').trim() !== '')
        return true;
    const home = process.env.DSH_HOME;
    if (home === undefined || home === '')
        return false;
    try {
        const raw = fs.readFileSync(path.join(home, 'credentials.json'), 'utf8');
        const entry = JSON.parse(raw).agents?.[agentId];
        const value = entry?.[key];
        return typeof value === 'string' && value.trim() !== '';
    }
    catch {
        return false;
    }
}
/**
 * 在 PATH 里解析可执行文件。
 *
 * 绝对/相对路径直接验可执行位；裸名走 PATH 扫描。不用 `which` 子进程——
 * 那要多一次 spawn，而且 which 在不同发行版上行为不一致（有的是 shell 内建）。
 */
export function resolveBinary(name) {
    if (name.includes('/')) {
        try {
            fs.accessSync(name, fs.constants.X_OK);
            return name;
        }
        catch {
            return undefined;
        }
    }
    for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
        if (dir === '')
            continue;
        const full = path.join(dir, name);
        try {
            fs.accessSync(full, fs.constants.X_OK);
            return full;
        }
        catch {
            /* 继续找下一个目录 */
        }
    }
    return undefined;
}
/**
 * 启动时探一次可用性。
 *
 * 装不上和跑挂了是两件事：前者是持久事实（重启也不会变），后者是环境瞬态。
 * 混在一起处理会让「没装」在冷却期过后被反复重试，每次都贡献一次假失败。
 */
export function probeAgents(registry, options = {}) {
    const resolve = options.resolve ?? resolveBinary;
    const available = [];
    const missing = [];
    for (const candidate of registry.all()) {
        const bin = candidate.command?.[0];
        // mcp 候选跑的是外部 server，检查它声明的 probeCommand；
        // subagent 类本层确实不驱动，保持判死。
        if (candidate.kind === 'subagent') {
            registry.markUnavailable(candidate.id);
            missing.push(candidate.id);
            continue;
        }
        const probeBin = candidate.probeCommand ?? bin;
        if (probeBin === undefined) {
            registry.markUnavailable(candidate.id);
            missing.push(candidate.id);
            continue;
        }
        if (resolve(probeBin) === undefined) {
            registry.markUnavailable(candidate.id);
            missing.push(candidate.id);
            continue;
        }
        // 命令在但凭据缺，同样不可用——而且要说清楚缺哪个。
        const lacking = (candidate.requiresEnv ?? []).filter((group) => !group.some((k) => hasEnv(k, candidate.id)));
        if (lacking.length > 0) {
            registry.markUnavailable(candidate.id);
            missing.push(candidate.id);
            continue;
        }
        registry.markAvailable(candidate.id);
        available.push(candidate.id);
    }
    return { available, missing };
}
/** 读文件头判断是不是可执行体。只读 4 字节，不解析格式。 */
function looksLikeBinary(file) {
    try {
        const fd = fs.openSync(file, 'r');
        try {
            const buf = Buffer.allocUnsafe(4);
            const read = fs.readSync(fd, buf, 0, 4, 0);
            if (read < 4)
                return false;
            const magic = buf.readUInt32BE(0);
            // ELF / PE(MZ) / Mach-O 32&64 / fat binary
            return (magic === 0x7f454c46 || // \x7fELF
                (buf[0] === 0x4d && buf[1] === 0x5a) || // MZ
                magic === 0xfeedface ||
                magic === 0xfeedfacf ||
                magic === 0xcafebabe ||
                magic === 0xcefaedfe ||
                magic === 0xcffaedfe);
        }
        finally {
            fs.closeSync(fd);
        }
    }
    catch {
        return false;
    }
}
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
/**
 * 判定目标形态。顺序是有讲究的：
 * 路径存在性先于命令判定——`/a/b c/d` 这种带空格的路径必须先被认出来，
 * 否则会被当成「命令 + 参数」派给错误的 agent。
 */
export function detectTargetShape(target, options = {}) {
    const t = target.trim();
    if (t === '')
        return 'unknown';
    if (/^https?:\/\//i.test(t) || /^wss?:\/\//i.test(t))
        return 'url';
    try {
        const stat = fs.statSync(t);
        if (stat.isDirectory())
            return 'directory';
        if (stat.isFile())
            return looksLikeBinary(t) ? 'binary' : 'file';
    }
    catch {
        /* 不是本地路径，继续往下判 */
    }
    const first = t.split(/\s+/)[0] ?? '';
    if (/\s/.test(t) && first !== '' && (options.resolve ?? resolveBinary)(first) !== undefined) {
        return 'command';
    }
    if (IPV4_RE.test(t))
        return 'host';
    if (!/[:/]/.test(t) && HOST_RE.test(t))
        return 'host';
    // 带端口的主机名 / IP，例如 example.com:8080
    if (/^[^/:]+:\d{1,5}$/.test(t))
        return 'host';
    return 'unknown';
}
/**
 * 候选对目标形态的适配度。
 *
 *   1   —— 明确声明能处理这个形态
 *   0.5 —— 没声明 accepts，什么都愿意试
 *   0   —— 明确声明不接受这个形态，不该派
 */
export function fitness(candidate, shape) {
    const accepts = candidate.accepts;
    if (accepts === undefined || accepts.length === 0)
        return 0.5;
    return accepts.includes(shape) ? 1 : 0;
}
// ── 输出解析器 ───────────────────────────────────────────────────────────────
function readIfExists(file) {
    try {
        return fs.readFileSync(file, 'utf8');
    }
    catch {
        return undefined;
    }
}
/** 取 JSON 载荷：先看文件，没有就从 stdout 里捞最外层花括号。 */
function loadJson(fileCandidates, stdout) {
    for (const file of fileCandidates) {
        const raw = readIfExists(file);
        if (raw !== undefined) {
            try {
                return JSON.parse(raw);
            }
            catch {
                /* 继续找 */
            }
        }
    }
    const trimmed = stdout.trim();
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start === -1 || end <= start)
        return undefined;
    try {
        return JSON.parse(trimmed.slice(start, end + 1));
    }
    catch {
        return undefined;
    }
}
/** SARIF 2.1.0：results 非空即有发现。corvus / semgrep / CodeQL 同格式。 */
export function sarifVerdict(doc) {
    const runs = doc?.runs;
    if (!Array.isArray(runs))
        return undefined;
    const levels = {};
    let total = 0;
    for (const run of runs) {
        const results = run.results;
        if (!Array.isArray(results))
            continue;
        for (const r of results) {
            total += 1;
            const level = String(r.level ?? 'unknown');
            levels[level] = (levels[level] ?? 0) + 1;
        }
    }
    const breakdown = Object.entries(levels)
        .map(([k, v]) => `${k}=${v}`)
        .join(' ');
    return { found: total > 0, detail: `${total} result(s)${breakdown === '' ? '' : ` (${breakdown})`}` };
}
/**
 * promptfoo eval JSON。
 *
 * 关键区分：`errors` 是评估过程出错（provider 挂、配置错），不是被测系统有问题。
 * 把 error 算成 found 就是编造发现；把 error 算成 clean 就是漏报。两者都不做——
 * 全是 error 时返回 undefined，让调度器记为 inconclusive。
 */
export function promptfooVerdict(doc) {
    const stats = doc?.results?.stats;
    if (stats === undefined)
        return undefined;
    const successes = stats.successes ?? 0;
    const failures = stats.failures ?? 0;
    const errors = stats.errors ?? 0;
    const judged = successes + failures;
    if (judged === 0)
        return undefined;
    return {
        found: failures > 0,
        detail: `${successes} pass / ${failures} fail / ${errors} error`,
        class: failures > 0 ? 'finding' : 'clean',
    };
}
/** corvus：读证据目录里的 report.sarif。 */
export function corvusVerdict(ctx) {
    // report.json 优先于 report.sarif。原先的顺序是反的（sarif 在前），于是
    // `exploitation_confirmed` 那段永远走不到——一个只有等级、没有确认语义的
    // 通用 SARIF 判定把 corvus 自己的判据整个盖掉了。这类错误不会报错，
    // 只会让「已利用确认」和「静态启发式」在报告里长得一模一样。
    const json = loadJson([path.join(ctx.evidenceDir, 'report.json')], '');
    const findings = json?.findings;
    if (Array.isArray(findings)) {
        const sev = {};
        let confirmed = 0;
        for (const f of findings) {
            const s = String(f.severity ?? 'unknown');
            sev[s] = (sev[s] ?? 0) + 1;
            if (f.exploitation_confirmed === true)
                confirmed += 1;
        }
        const breakdown = Object.entries(sev)
            .map(([k, v]) => `${k}=${v}`)
            .join(' ');
        return {
            found: findings.length > 0,
            detail: `${String(findings.length)} finding(s)${breakdown === '' ? '' : ` (${breakdown})`}, ${String(confirmed)} exploitation-confirmed`,
            // corvus 绝大多数是静态启发式：inputSchema 要求了凭据字段、工具名撞内置名……
            // 那些是**暴露面**，不是已确认漏洞。只有它自己标了 exploitation_confirmed 的
            // 才算 finding。把所有条目都报成 finding，等于用 36 条噪音换 0 条可用线索。
            class: confirmed > 0 ? 'finding' : 'exposure',
        };
    }
    const doc = loadJson([path.join(ctx.evidenceDir, 'report.sarif')], '');
    if (doc === undefined)
        return undefined;
    return sarifVerdict(doc);
}
/** promptfoo：读证据目录里的 out.json。 */
export function promptfooFileVerdict(ctx) {
    const doc = loadJson([path.join(ctx.evidenceDir, 'promptfoo.json')], ctx.stdout);
    return promptfooVerdict(doc);
}
/**
 * rabin2 `-Ij`：解析二进制加固状态。
 *
 * 「有发现」在这里的语义是**保护缺失**（可被利用的前提），不是找到 CVE。
 * 缺 canary / NX / PIE / RELRO 都可验证，也不是启发式猜测——读的就是 ELF 头。
 */
export function rabinVerdict(ctx) {
    const doc = loadJson([], ctx.stdout);
    const info = doc?.info;
    if (info === undefined || typeof info.bintype !== 'string')
        return undefined;
    const weak = [];
    if (info.canary === false)
        weak.push('no canary');
    if (info.nx === false)
        weak.push('no nx');
    if (info.pic === false)
        weak.push('no pie');
    if (typeof info.relro === 'string' && info.relro.toLowerCase() === 'none')
        weak.push('no relro');
    return {
        found: weak.length > 0,
        detail: `${info.bintype}/${String(info.arch)}: ${weak.length > 0 ? weak.join(', ') : 'standard mitigations present'}`,
        class: weak.length > 0 ? 'exposure' : 'clean',
    };
}
/**
 * nuclei `-jsonl`：每行一个命中，没有命中时输出为空。
 *
 * 判据的可靠性来自这里：nuclei 加载模板失败会非零退出（由 classifyProcess 处理），
 * 正常跑完而无命中就是干净的零行输出。所以「exit 0 且零行」可以作为无发现，
 * 这与其他工具「exit 0 但什么也没说」的情况不同。
 */
export function nucleiVerdict(ctx) {
    const rows = [];
    let malformed = 0;
    for (const line of ctx.stdout.split('\n')) {
        const t = line.trim();
        if (!t.startsWith('{'))
            continue;
        try {
            rows.push(JSON.parse(t));
        }
        catch {
            malformed += 1;
        }
    }
    if (rows.length === 0) {
        if (malformed > 0)
            return undefined;
        if (ctx.exitCode !== 0)
            return undefined;
        // exit 0 + 零行 + stderr 里有错误噪音，说明这次扫描可能根本没真的跑起来。
        // 这时「零命中」不能当成「目标干净」——那正是漏报的典型来源。
        if (/\b(err|error|fatal|failed|could not|no templates)\b/i.test(ctx.stderr))
            return undefined;
        return { found: false, detail: '0 matches' };
    }
    const sev = {};
    const templates = new Set();
    for (const r of rows) {
        const info = r.info;
        const s = typeof info?.severity === 'string' ? info.severity : 'unknown';
        sev[s] = (sev[s] ?? 0) + 1;
        if (typeof r['template-id'] === 'string')
            templates.add(r['template-id']);
    }
    const breakdown = Object.entries(sev).map(([k, v]) => `${k}=${v}`).join(' ');
    // info/low 是指纹与提示，medium 以上才是需要处理的问题。
    const serious = (sev['critical'] ?? 0) + (sev['high'] ?? 0) + (sev['medium'] ?? 0) > 0;
    return {
        found: true,
        detail: `${rows.length} match(es) across ${templates.size} template(s) (${breakdown})`,
        class: serious ? 'finding' : 'exposure',
    };
}
/**
 * checksec `--output=json`。
 *
 * 结构：`{ "<path>": { relro, canary, nx, pie, rpath, runpath, symbols, ... } }`。
 * 「有发现」在这里指**加固缺失**——relro/canary/nx/pie 任一为 "no"。
 * `pie: "not_elf"` 表示不是 ELF，不算缺失。
 */
/**
 * 隐写检测的判据。
 *
 * zsteg 扫完没有任何嵌入时输出 `none`（或空）；命中时逐行形如
 * `b1,rgb,lsb,xy .. text: "..."`。这里只认后半段的 `text:/file:/meta:`
 * 标记——位平面名字本身不是证据，每个 PNG 都有位平面。
 *
 * 注意 PNG 的 chunk 名字（b1,rgba,msb）在正常图里也会出现，靠它判定必然误报，
 * 这正是 `control` 用一张干净 PNG 校准的原因：干净图上它必须报 clean。
 */
export function stegoVerdict(ctx) {
    const out = `${ctx.stdout}`.trim();
    if (out === '') {
        return ctx.exitCode === 0 ? { found: false, class: 'clean', detail: 'no output' } : undefined;
    }
    // ⚠️ 实测：zsteg 对一张纯渐变 PNG 也会输出二十多条 `text:`（"U" repeated 64 times
    // 这类规律性填充），甚至把 IHDR 认成 Photoshop swatch。所以 `text:` 不能作为判据，
    // 只认确凿的 `file:` —— 且排除它自己会误认的那几个容器类型。
    const hit = out
        .split('\n')
        .map((l) => l.trim())
        .find((l) => /file:/i.test(l) && !/(PNG|JPEG|GIF|Photoshop|Zip archive)/i.test(l));
    if (hit === undefined) {
        if (/^none$/im.test(out))
            return { found: false, class: 'clean', detail: 'no embedded data' };
        // 只有 text/meta 行：证明不了有隐写，也证明不了没有——留 inconclusive。
        return undefined;
    }
    return { found: true, class: 'exposure', detail: hit.slice(0, 200) };
}
/**
 * 文件雕刻 / 嵌入检测的判据。
 *
 * binwalk 的签名表每行以「十进制偏移 + 0x十六进制 + 描述」开头。**只有容器自身的
 * 声明不算发现**：一张普通 PNG 也会被识别出 `PNG image`，那是文件头不是隐藏文件。
 * 出现第二个签名、或者签名不是容器类型，才算嵌入。
 */
export function carveVerdict(ctx) {
    const rows = ctx.stdout
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => /^\d+\s+0x[0-9A-Fa-f]+\s+/.test(l));
    if (rows.length === 0)
        return undefined;
    const containerOnly = rows.length === 1 && /(PNG|JPEG|GIF|ELF|Zip) (image|archive|executable)/i.test(rows[0]);
    if (containerOnly) {
        return { found: false, class: 'clean', detail: `only container signature: ${rows[0].slice(0, 100)}` };
    }
    return {
        found: true,
        class: 'exposure',
        detail: rows.slice(0, 5).map((r) => r.slice(0, 80)).join(' | ').slice(0, 300),
    };
}
/**
 * ROP gadget 的判据。
 *
 * 这**不是漏洞发现**：几乎每个二进制都能找到 gadget，「有 pop rdi」不代表可利用。
 * 它提供的是攻击构造的原材料清单，所以只能报 exposure，并且只有在找到
 * 控制寄存器那一类时才值得记一笔——`ret` 满地都是，记它没有信息量。
 */
export function gadgetVerdict(ctx) {
    const out = ctx.stdout;
    if (out.trim() === '')
        return undefined;
    const useful = ['pop rdi', 'pop rsi', 'pop rdx', 'pop rax', 'syscall', 'leave ; ret'];
    const hits = useful.filter((g) => new RegExp(g.replace(/ /g, '\\s*;?\\s*'), 'i').test(out));
    if (hits.length === 0)
        return { found: false, class: 'clean', detail: 'no register-control gadgets' };
    return { found: true, class: 'exposure', detail: `gadgets: ${hits.join(', ')}` };
}
/**
 * garak 的判据。
 *
 * 它按 probe 家族批量打目标 LLM，每条探针的结论落在输出里的 `PASS`/`FAIL` 标记上。
 * 只有出现 FAIL 才算「这个探针打穿了」——那确实是可利用的问题（越狱、提示注入、
 * 数据泄露），记 finding 而不是 exposure。
 *
 * 注意它和 web 扫描器的区别：这里没有「正常请求对照」可用，因为正常 prompt
 * 本来就该被拒；判据只能是探针自己的 PASS/FAIL 语义。
 */
export function garakVerdict(ctx) {
    const out = `${ctx.stdout}\n${ctx.stderr}`;
    const fails = out.split('\n').map((l) => l.trim()).filter((l) => /\bFAIL\b/.test(l));
    if (fails.length > 0) {
        return { found: true, class: 'finding', detail: fails.slice(0, 3).join(' | ').slice(0, 260) };
    }
    if (/\bPASS\b/i.test(out) || /report written to/i.test(out)) {
        return { found: false, class: 'clean', detail: 'no probe failures' };
    }
    return undefined;
}
/**
 * RSA 攻击的判据。
 *
 * RsaCtfTool 成功时输出 PEM 私钥或明文；失败时只是把试过的攻击列一遍。
 * 判据只能是「有没有真的恢复出私钥/明文」——列出攻击名字不算发现，
 * 那和 nuclei 把 info 级指纹报成漏洞是同一类错误。
 */
export function rsaVerdict(ctx) {
    const out = `${ctx.stdout}`;
    if (/BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY/.test(out)) {
        return { found: true, class: 'finding', detail: 'private key recovered' };
    }
    if (/\bFLAG\{|flag\{/.test(out)) {
        const m = out.match(/(FLAG\{[^}]{1,200}\}|flag\{[^}]{1,200}\})/);
        return { found: true, class: 'finding', detail: m?.[1] ?? 'plaintext recovered' };
    }
    if (/No attack success|failed|no key found/i.test(out)) {
        return { found: false, class: 'clean', detail: 'all attacks exhausted' };
    }
    return undefined;
}
/**
 * 云存储桶的判据。
 *
 * 只认「确实存在且可列出/可写」——桶不存在、403 私有、DNS 无解析都不算发现。
 * 原文工具会把「桶不存在」也打印出来（它随后会尝试劫持），所以不能见输出就报。
 */
export function bucketVerdict(ctx) {
    const out = `${ctx.stdout}`;
    if (out.trim() === '')
        return undefined;
    if (/(可以劫持|hijack|NoSuchBucket|不存在)/i.test(out)) {
        return { found: true, class: 'exposure', detail: 'bucket name dangling — takeover candidate' };
    }
    if (/(公开读|public-read|ListBucket|object list|可写|writeable)/i.test(out)) {
        return { found: true, class: 'finding', detail: 'bucket publicly accessible' };
    }
    if (/(私有|private|AccessDenied|403)/i.test(out)) {
        return { found: false, class: 'clean', detail: 'bucket exists but private' };
    }
    return undefined;
}
export function checksecVerdict(ctx) {
    const doc = loadJson([], ctx.stdout);
    if (doc === undefined)
        return undefined;
    const keys = Object.keys(doc);
    if (keys.length === 0)
        return undefined;
    const first = doc[keys[0]];
    if (first === undefined || typeof first !== 'object')
        return undefined;
    const missing = [];
    for (const field of ['relro', 'canary', 'nx', 'pie']) {
        const v = first[field];
        if (typeof v === 'string' && v.toLowerCase() === 'no')
            missing.push(field);
    }
    const present = ['relro', 'canary', 'nx', 'pie'].filter((f) => {
        const v = first[f];
        return typeof v === 'string' && (v.toLowerCase() === 'yes' || v.toLowerCase() === 'full');
    });
    return {
        found: missing.length > 0,
        detail: missing.length > 0 ? `missing: ${missing.join(', ')}` : `hardened: ${present.join(', ')}`,
        class: missing.length > 0 ? 'exposure' : 'clean',
    };
}
/**
 * enum4linux-ng 的 JSON 报告。
 *
 * 「有发现」= 无凭据就能拿到东西：空会话可建立、guest 可登录。
 * SMB 签名未强制虽然也是风险（中继攻击前提），但在非域控环境属常见默认，
 * 单独算一条会让这个方向噪音大于信号——只放进 detail，不单独构成 found。
 */
export function enum4linuxVerdict(ctx) {
    const doc = loadJson([path.join(ctx.evidenceDir, 'enum4linux.json')], ctx.stdout);
    if (doc === undefined)
        return undefined;
    // 目标上根本没有 SMB/LDAP 监听（四个 listener 全 connection refused）。
    // 这不是「跑不通」，是**确定的负面结论**：这个攻击面在这台主机上不存在。
    // 判成 inconclusive 会让这条信息被浪费掉——丞相把它当成「没结论」还会再派一次，
    // 而正确的结果是给这个方向打 coverage 戳、不再重复。
    const listeners = doc.listeners;
    if (doc.sessions === undefined && listeners !== undefined) {
        const entries = Object.entries(listeners);
        const reachable = entries.filter(([, v]) => v?.accessible === true).map(([k]) => k);
        if (entries.length > 0 && reachable.length === 0) {
            return {
                found: false,
                class: 'clean',
                detail: `no SMB/LDAP listener reachable (${entries.map(([k, v]) => `${k}:${String(v?.port ?? '?')}`).join(', ')} all refused)`,
            };
        }
        if (reachable.length > 0) {
            // 端口开着却没拿到 sessions：enum4linux 中途断了，这才是真的不清楚。
            return undefined;
        }
    }
    if (doc.sessions === undefined)
        return undefined;
    const nullSession = doc.sessions['null'] === true;
    const guestSession = doc.sessions['guest'] === true;
    const signingRequired = doc.smb_dialects?.['SMB signing required'] === true;
    const shareNames = Object.keys(doc.shares ?? {});
    const findings = [];
    if (nullSession)
        findings.push('null session accepted');
    if (guestSession)
        findings.push('guest logon accepted');
    if (shareNames.length > 0)
        findings.push(`shares: ${shareNames.join(',')}`);
    const notes = [];
    if (!signingRequired)
        notes.push('SMB signing not required');
    return {
        found: nullSession || guestSession,
        detail: `${findings.join('; ')}${notes.length > 0 ? ` [${notes.join('; ')}]` : ''}`,
        class: nullSession || guestSession ? 'finding' : 'exposure',
    };
}
/**
 * rea `analyze`：结构化逆向报告。
 *
 * 它的默认 operation 是 `binary_overview`——**侦察，不是漏洞判定**。
 * 所以这里刻意返回 `found:false` 且**不设 class**：
 *   - 判 inconclusive 是错的：它确实跑完了，也给出了确定事实
 *   - 判 clean 更错：它根本没有去找漏洞，给 coverage 打上「已清扫」的戳
 *     会让丞相以为这个方向的攻击面已被排除
 * 只把确定的事实（段/过程/字符串计数 + evidence id）交给上层，让 detail 自己说话。
 *
 * 只认 binary_overview。其它 operation 的语义这里没有依据，返回 undefined 不猜。
 */
export function reaVerdict(ctx) {
    const text = ctx.stdout;
    if (!/^operation:\s*binary_overview\s*$/m.test(text))
        return undefined;
    const num = (key) => {
        const m = new RegExp(`^\\s*${key}:\\s*(\\d+)\\s*$`, 'm').exec(text);
        return m?.[1] === undefined ? undefined : Number(m[1]);
    };
    const segments = num('segment_count');
    const procedures = num('procedure_count');
    const strings = num('string_count');
    const evidence = /^evidence_id:\s*(\S+)/m.exec(text)?.[1];
    // provider 段有多层嵌套（analysis_profile.parameters.upstream_analysis_profile.provider.id），
    // 不按缩进层级匹配——层数一改就静默退化成 unknown。
    const provider = /^\s*id:\s*ghidra\s*$/m.test(text) ? 'ghidra' : 'unknown';
    if (segments === undefined && procedures === undefined && strings === undefined)
        return undefined;
    const parts = [
        segments === undefined ? undefined : `${String(segments)} segments`,
        procedures === undefined ? undefined : `${String(procedures)} procedures`,
        strings === undefined ? undefined : `${String(strings)} strings`,
    ].filter((x) => x !== undefined);
    return {
        found: false,
        detail: `binary overview via ${provider}: ${parts.join(', ')} — 结构侦察，未做安全判定` +
            `${evidence === undefined ? '' : ` (evidence ${evidence.slice(0, 24)}…)`}`,
    };
}
/**
 * sslyze `--json_out`：TLS 配置审计。
 *
 * 「有发现」= 可被实际利用的配置缺陷：支持废弃协议、Heartbleed、ROBOT、
 * 启用压缩（CRIME）、允许客户端触发重协商 DoS。
 *
 * 刻意不把「弱密码套件」单独算一条：几乎所有真实服务都有几个 3DES/CBC 套件，
 * 把它们算成发现会让这个方向噪音大于信号。只报能直接导致攻击的那些。
 */
export function sslyzeVerdict(ctx) {
    const doc = loadJson([path.join(ctx.evidenceDir, 'sslyze.json')], ctx.stdout);
    const scan = doc?.server_scan_results?.[0]?.scan_result;
    if (scan === undefined)
        return undefined;
    const findings = [];
    const ok = (name) => {
        const r = scan[name];
        return r?.status === 'COMPLETED' ? (r.result ?? {}) : undefined;
    };
    for (const [name, label] of [
        ['ssl_2_0_cipher_suites', 'SSL 2.0'],
        ['ssl_3_0_cipher_suites', 'SSL 3.0'],
        ['tls_1_0_cipher_suites', 'TLS 1.0'],
        ['tls_1_1_cipher_suites', 'TLS 1.1'],
    ]) {
        const r = ok(name);
        if (r?.['is_tls_version_supported'] === true)
            findings.push(`${label} enabled`);
    }
    if (ok('heartbleed')?.['is_vulnerable_to_heartbleed'] === true)
        findings.push('Heartbleed');
    const robot = ok('robot')?.['robot_result'];
    if (typeof robot === 'string' && robot.startsWith('VULNERABLE'))
        findings.push(`ROBOT (${robot})`);
    if (ok('tls_compression')?.['supports_compression'] === true)
        findings.push('TLS compression (CRIME)');
    if (ok('session_renegotiation')?.['is_vulnerable_to_client_renegotiation_dos'] === true) {
        findings.push('client-initiated renegotiation DoS');
    }
    if (ok('openssl_ccs_injection')?.['is_vulnerable_to_ccs_injection'] === true)
        findings.push('CCS injection');
    const exploitable = findings.some((f) => /Heartbleed|ROBOT|CCS/.test(f));
    return {
        found: findings.length > 0,
        detail: findings.length > 0 ? findings.join(', ') : 'no exploitable TLS misconfiguration',
        class: findings.length === 0 ? 'clean' : exploitable ? 'finding' : 'exposure',
    };
}
/**
 * strix 的报告：`<cwd>/strix_runs/<run>/vulnerabilities.json`。
 *
 * 判据只能从这里读，不能靠退出码：strix 用 exit 2 表示「有发现」，
 * 而 2 在通用语义里是用法错误，两者撞车。读文件没有歧义。
 */
export function strixVerdict(ctx) {
    const runsDir = path.join(ctx.evidenceDir, 'strix_runs');
    let entries;
    try {
        entries = fs.readdirSync(runsDir);
    }
    catch {
        return undefined;
    }
    // 真实产物是 findings.sarif，不是 vulnerabilities.json（那是旧版本/内部接口）。
    // 取最新一次 run：并发派活时可能有多个目录，按 mtime 定。
    let newest;
    let newestAt = -1;
    for (const name of entries) {
        const file = path.join(runsDir, name, 'findings.sarif');
        try {
            const stat = fs.statSync(file);
            if (stat.mtimeMs > newestAt) {
                newestAt = stat.mtimeMs;
                newest = file;
            }
        }
        catch {
            /* 这次 run 还没写报告 */
        }
    }
    if (newest === undefined)
        return undefined;
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(newest, 'utf8'));
    }
    catch {
        return undefined;
    }
    const runs = parsed.runs;
    if (!Array.isArray(runs))
        return undefined;
    // SARIF 里混着两类东西：`strix-coverage/*` 是「这个方面我查过了/建议复查」的覆盖度条目，
    // 不是发现。把它们算成漏洞，会让每一轮都报一堆假发现——这是 strix 特有的坑。
    const sev = {};
    let real = 0;
    let coverage = 0;
    for (const run of runs) {
        const results = run.results;
        if (!Array.isArray(results))
            continue;
        for (const r of results) {
            const ruleId = String(r.ruleId ?? '');
            if (ruleId.startsWith('strix-coverage/')) {
                coverage += 1;
                continue;
            }
            real += 1;
            const level = String(r.level ?? 'unknown');
            sev[level] = (sev[level] ?? 0) + 1;
        }
    }
    const breakdown = Object.entries(sev).map(([k, n]) => `${k}=${n}`).join(' ');
    return {
        found: real > 0,
        detail: `${String(real)} finding(s)${breakdown === '' ? '' : ` (${breakdown})`}` +
            (coverage > 0 ? `, ${String(coverage)} coverage note(s) excluded` : ''),
        class: real > 0 ? 'finding' : 'clean',
    };
}
/**
 * strix 的 LLM 配置。
 *
 * 它只从环境变量或 `--config` 指向的 JSON 读（结构是 `{"env": {...}}`）。
 * 不能为它污染全局 env——同进程里别的 agent 也在用那份环境。
 * 所以每次派活现写一份到证据目录。
 */
function writeStrixConfig(evidenceDir) {
    // invocation 在 buildArgv 阶段就被调用，那时 evidenceDir 还没建
    // （createQueueAttempt 是在之后才 mkdir 的）。不自己建就会 ENOENT。
    fs.mkdirSync(evidenceDir, { recursive: true });
    const file = path.join(evidenceDir, 'strix-config.json');
    const key = process.env.LLM_API_KEY ?? process.env.OPENAI_API_KEY ?? '';
    fs.writeFileSync(file, JSON.stringify({
        env: {
            STRIX_LLM: process.env.STRIX_LLM ?? 'openai/deepseek-flash',
            LLM_API_KEY: key,
            LLM_API_BASE: process.env.STRIX_LLM_BASE ?? 'https://api.deepseek.com/v1',
            // 默认镜像在 ghcr.io，直连拉不动。用已经落地的镜像 tag——
            // 换机器/换 tag 时只改这里，不用动代码。
            STRIX_IMAGE: process.env.STRIX_IMAGE ?? 'ghcr.nju.edu.cn/usestrix/strix-sandbox:1.3.0',
        },
    }, null, 2), 'utf8');
    return file;
}
/**
 * radare2 的函数列表（`aflj`）。
 *
 * 「有发现」= 调用了危险函数。这是可判定的：`strcpy`/`gets`/`system`/`sprintf`
 * 出现在动态导入里，就是一条实打实的攻击面线索，不是启发式猜测。
 *
 * 刻意不把「函数数量」「字符串数量」算成发现——那些是解剖结果，不是结论。
 */
const DANGEROUS_IMPORTS = [
    'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'popen', 'execve', 'execl',
    'getenv', 'mktemp', 'tmpnam', 'scanf', 'sscanf', 'memcpy', 'alloca',
];
export function radareVerdict(ctx) {
    const text = ctx.stdout.trim();
    const start = text.indexOf('[');
    const end = text.lastIndexOf(']');
    if (start === -1 || end <= start)
        return undefined;
    let fns;
    try {
        fns = JSON.parse(text.slice(start, end + 1));
    }
    catch {
        return undefined;
    }
    if (!Array.isArray(fns))
        return undefined;
    const names = fns
        .map((f) => String(f.name ?? ''))
        .filter((n) => n.length > 0);
    const risky = names.filter((n) => DANGEROUS_IMPORTS.some((d) => new RegExp(`(^|[._])${d}(@|$)`, 'i').test(n)));
    return {
        found: risky.length > 0,
        detail: `${String(names.length)} function(s)` +
            (risky.length === 0 ? ', no dangerous import' : `, risky: ${risky.slice(0, 6).join(', ')}`),
        class: risky.length > 0 ? 'exposure' : 'clean',
    };
}
/** semgrep `--json`：results 非空即有发现。 */
/** semgrep `--json`：results 非空即有发现。 */
export function semgrepVerdict(ctx) {
    const doc = loadJson([], ctx.stdout);
    const results = doc?.results;
    if (!Array.isArray(results))
        return undefined;
    return {
        found: results.length > 0,
        detail: `${results.length} match(es)`,
        class: results.length > 0 ? 'finding' : 'clean',
    };
}
// ── 默认清单 ─────────────────────────────────────────────────────────────────
/**
 * 只登记**有确切发行版**的 agent。
 *
 * 曾经凭记忆写过 `reap`、`@mcp-scan/cli` 这类名字，实测 PyPI/npm 都不存在。
 * 注册表里放不存在的东西，调度器会反复选中它反复失败，看起来像环境坏了。
 * 每个条目要么本机已装并跑通，要么给出确切包名与安装命令。
 */
export const DEFAULT_AGENTS = [
    // ── AI / LLM 安全 ──
    {
        id: 'promptfoo',
        direction: 'ai-security',
        kind: 'cli',
        command: ['promptfoo'],
        capability: '提示词回归与红队评估：断言驱动的批量用例，支持多模型对比与 CI 集成',
        priority: 10,
        accepts: ['file'],
        cost: 'moderate',
        defaultTimeoutMs: 300_000,
        invocation: (target, ctx) => [
            'eval',
            '-c', target,
            '-o', path.join(ctx.evidenceDir, 'promptfoo.json'),
            '--no-progress-bar',
            '--no-cache',
            '--no-table',
        ],
        verdict: promptfooFileVerdict,
    },
    {
        id: 'garak',
        direction: 'ai-security',
        kind: 'cli',
        // 装在独立 venv 里：系统 Python 3.14 装不动它的依赖链（torch/transformers 实测吃掉 5.9G）。
        // probe 查 command[0]，venv 的 python 在就等于 garak 在。
        command: ['/root/proj/agents/venvs/aisec/bin/python', '-m', 'garak'],
        capability: 'LLM 漏洞扫描：探针覆盖越狱、数据泄露、提示注入、编码攻击，按家族批量打目标端点',
        priority: 20,
        accepts: ['url', 'host', 'unknown'],
        cost: 'expensive',
        defaultTimeoutMs: 1_800_000,
        invocation: (target) => [
            '--model_type', 'rest',
            '--model_name', target,
            '--probes', 'promptinject,dan,leakreplay,encoding',
            '--report_prefix', 'garak',
        ],
        verdict: garakVerdict,
        // ⚠️ 不设 requiresEnv：这一层扫的是**靶场目标端点**，用的是目标自己的凭据，
        // 不是本机的 OPENAI_API_KEY。原来那条要求会让 garak 在没配 key 的比赛机器上
        // 被直接判成不可用，而它本来完全跑得动。
        requires: '目标须是 OpenAI 兼容的 /chat/completions 端点；首次运行会拉取探针数据集；' +
            '单轮可达十几分钟，别用默认超时卡它',
    },
    {
        id: 'pyrit',
        direction: 'ai-security',
        // ⚠️ 原来是 kind:'subagent' + provider:'pyrit'，但 DSH 侧没有 pyrit 这个 provider，
        // 那个形态永远不会就绪。PyRIT 的真实形态是「客户端 + 后端服务」，所以改成 CLI，
        // 由调用方先 `pyrit_scan start-server` 再打。
        kind: 'cli',
        command: ['/root/proj/agents/venvs/aisec/bin/pyrit_scan'],
        capability: '多轮红队编排：编排器-转换器-评分器三段式，可编程攻击流程',
        priority: 30,
        requires: '本执行层尚未接入 subagent provider（只驱动 cli/mcp）',
    },
    // ── MCP / Agent 安全 ──
    {
        id: 'corvus',
        direction: 'mcp-security',
        kind: 'cli',
        command: ['corvus'],
        capability: 'MCP server 安全评估：34 个模块，SARIF 输出 + risk score + 历史 diff',
        priority: 10,
        accepts: ['command', 'url'],
        cost: 'moderate',
        defaultTimeoutMs: 180_000,
        invocation: (target, ctx) => ['scan', target, '--output-dir', ctx.evidenceDir, '--sarif'],
        verdict: corvusVerdict,
    },
    {
        id: 'mcp-scan',
        direction: 'mcp-security',
        kind: 'cli',
        // 上游已改名 snyk-agent-scan（旧名只留一条改名警告就直接退出）。
        // 装在独立 venv：pypi 版依赖 RapidFuzz 等被 debian 占用的包，系统 pip 装不动。
        command: ['/root/proj/agents/venvs/aisec/bin/snyk-agent-scan'],
        capability: 'MCP 配置与工具描述扫描：提示注入、工具投毒、跨 server 影子攻击（Snyk Agent Scan）',
        priority: 20,
        // 吃的是配置文件路径，不是 MCP 的启动命令——这两个形态经常被混为一谈。
        accepts: ['file'],
        cost: 'cheap',
        defaultTimeoutMs: 180_000,
        // 输入是 MCP 配置文件（不是 URL），且核心判定依赖 Snyk 云端分析；
        // 离线时静态检查能跑但结论为空。已实测：无云端时只剩一条改名警告。
        invocation: (target, ctx) => [
            'scan', target,
            '--json',
            '--dangerously-run-mcp-servers',
            '--suppress-mcpserver-io=true',
            '--storage-file', path.join(ctx.evidenceDir, 'mcp-scan.json'),
        ],
        requires: 'pip install mcp-scan（已改名 snyk-agent-scan；完整判定需 Snyk 云端 API）',
    },
    // ── 代码审计 ──
    {
        id: 'semgrep',
        direction: 'code-audit',
        kind: 'cli',
        // 独立 venv：semgrep 与 mcp-scan 抢 opentelemetry 版本，装同一个环境会把两边都弄坏。
        // 异构 agent 各自的依赖冲突是常态，一个 agent 一个 venv 才是可持续的做法。
        command: ['/root/proj/agents/venvs/semgrep/bin/semgrep'],
        capability: '多语言静态分析：污点追踪与规则匹配，JSON 输出可直接进证据链',
        priority: 10,
        accepts: ['directory', 'file'],
        cost: 'cheap',
        invocation: (target) => ['--config', 'auto', '--json', '--quiet', target],
        verdict: semgrepVerdict,
        // --config auto 首次要从 registry 下规则，冷缓存时可能要几分钟。
        // 用 300s 去卡它，系统会把「慢」记成「坏」——实测首次 240s 会被判 terminated。
        defaultTimeoutMs: 900_000,
        // --config auto 会去 semgrep registry 拉规则，网络受限时表现为超时而不是报错。
        // 离线环境要换成本地规则目录：--config /path/to/rules。
        requires: '--config auto 需要访问 semgrep registry；离线时改用本地规则目录',
    },
    // ── 二进制 / 逆向 ──
    {
        id: 'checksec',
        direction: 'binary-reverse',
        control: {
            argv: ['checksec', '--file=$TARGET', '--output=json'],
            target: '/usr/bin/ls',
            expect: 'clean',
            note: '发行版打包的 ls 加固齐全（relro=full canary/nx/pie=yes）；它若也报缺保护，说明检测或环境有问题',
        },
        kind: 'cli',
        command: ['checksec'],
        capability: 'ELF 加固审计：RELRO / canary / NX / PIE / fortify 逐项判定，JSON 输出',
        priority: 20,
        accepts: ['binary'],
        cost: 'cheap',
        defaultTimeoutMs: 30_000,
        invocation: (target) => [`--file=${target}`, '--output=json'],
        verdict: checksecVerdict,
    },
    {
        id: 'rabin2',
        direction: 'binary-reverse',
        control: {
            argv: ['rabin2', '-I', '$TARGET'],
            target: '/usr/bin/ls',
            expect: 'clean',
            note: '同上：用已知加固的样本校准 rabin2 的判读',
        },
        kind: 'cli',
        command: ['rabin2'],
        capability: '二进制加固状态检查：canary / NX / PIE / RELRO 缺失即暴露利用前提',
        priority: 10,
        accepts: ['binary'],
        cost: 'cheap',
        defaultTimeoutMs: 30_000,
        invocation: (target) => ['-Ij', target],
        verdict: rabinVerdict,
    },
    {
        id: 'adaptix',
        direction: 'post-exploit',
        kind: 'cli',
        command: ['adaptix'],
        capability: 'AdaptixC2：模块化 C2，后渗透阶段的会话管理与横向（需先取得立足点）',
        // 排在后面：C2 是重活，不该在任何情况下被优先选中。
        priority: 80,
        accepts: ['host'],
        cost: 'expensive',
        requires: '需要自行编译 C2 server 与 agent（C++/Qt 依赖），且要先有一个已控主机作起点；' +
            '它产出的是「会话」不是「发现」，本层没有对应判据，接口留待后续',
    },
    {
        id: 'radare2',
        direction: 'binary-reverse',
        kind: 'cli',
        command: ['r2'],
        capability: '深度解剖：函数列表、反汇编、交叉引用、字符串，JSON 可解析',
        priority: 40,
        accepts: ['binary'],
        cost: 'cheap',
        defaultTimeoutMs: 300_000,
        // -e scr.color=0 关掉 ANSI 颜色码；不加的话 JSON 里混着转义序列，解析必错。
        invocation: (target) => ['-q', '-e', 'scr.color=0', '-c', 'aaa; aflj', target],
        verdict: radareVerdict,
    },
    {
        id: 'rea',
        direction: 'binary-reverse',
        kind: 'cli',
        command: ['rea'],
        capability: '逆向工作台：原生二进制、JS/Electron、.NET 的结构化分析，输出带证据与局限说明。' +
            '默认 analyze 出的是 binary_overview（段/函数/字符串清单 + 证据 id），属于**侦察**；' +
            '它不做漏洞判定，所以「无发现」不表示该二进制安全。',
        priority: 30,
        accepts: ['binary', 'directory', 'file'],
        cost: 'moderate',
        defaultTimeoutMs: 600_000,
        invocation: (target) => ['analyze', target],
        verdict: reaVerdict,
        // 系统 apt 的 Ghidra 是 12.2，rea 要求 12.1.x。单独装一份 12.1.4 指过去，
        // 比为一个工具降级系统包安全——apt 那份还要给 cyberstrike 等其他调用方用。
        env: { GHIDRA_INSTALL_DIR: '/root/proj/agents/ghidra1214/ghidra_12.1.4_PUBLIC' },
        requires: '原生分析需要 Ghidra 12.1.x（由 env.GHIDRA_INSTALL_DIR 指向项目内那份 12.1.4）或 IDA/Hopper；' +
            '静态 JS/Electron 分析不需要引擎，可跑',
    },
    {
        id: 'toolfuzz',
        direction: 'binary-reverse',
        kind: 'subagent',
        capability: 'Agent 工具函数灰盒模糊测试：探测参数边界崩溃与校验绕过',
        priority: 90,
        requires: '库形态（python 包），需为每个被测工具写 harness，不能当 CLI 直接扫目标',
    },
    // ── 通过 MCP server 暴露的工具（CyberStrikeAI，81 个工具里挑了判据明确的）──
    {
        id: 'cyberstrike-sqlmap',
        probeCommand: '/root/proj/agents/cyberstrike/CyberStrikeAI-main/cyberstrike-mcp',
        direction: 'web-pentest',
        kind: 'mcp',
        capability: 'sqlmap（经 CyberStrikeAI MCP）：自动化 SQL 注入检测，输出明确可判',
        priority: 30,
        accepts: ['url'],
        cost: 'moderate',
        defaultTimeoutMs: 600_000,
        requires: '需要 CyberStrikeAI 的 mcp-stdio 可执行文件与 config.yaml',
    },
    {
        id: 'cyberstrike-dirsearch',
        probeCommand: '/root/proj/agents/cyberstrike/CyberStrikeAI-main/cyberstrike-mcp',
        direction: 'web-pentest',
        kind: 'mcp',
        capability: 'dirsearch（MCP）：目录与文件发现',
        priority: 40,
        accepts: ['url'],
        cost: 'cheap',
        defaultTimeoutMs: 600_000,
        requires: '需要 CyberStrikeAI 的 mcp-stdio 与 config.yaml；且宿主机要有 dirsearch 命令（它内部 fork 调用）',
    },
    {
        id: 'cyberstrike-nmap',
        probeCommand: '/root/proj/agents/cyberstrike/CyberStrikeAI-main/cyberstrike-mcp',
        direction: 'internal-ad',
        kind: 'mcp',
        capability: 'nmap（MCP）：端口与服务识别，内网侦察的起点',
        priority: 30,
        accepts: ['host', 'url'],
        cost: 'cheap',
        defaultTimeoutMs: 600_000,
        requires: '需要 CyberStrikeAI 的 mcp-stdio 可执行文件与 config.yaml',
    },
    {
        id: 'cyberstrike-ghidra',
        probeCommand: '/root/proj/agents/cyberstrike/CyberStrikeAI-main/cyberstrike-mcp',
        direction: 'binary-reverse',
        kind: 'mcp',
        capability: 'ghidra（MCP）：反汇编与反编译，补上我们没有的深度静态分析',
        priority: 40,
        accepts: ['binary', 'file'],
        cost: 'moderate',
        defaultTimeoutMs: 900_000,
        requires: 'Ghidra 已装（analyzeHeadless 在 PATH，直跑 22s 成功），但 CyberStrikeAI 的工具执行层调它 3 秒即失败——' +
            '是它自己的调用问题，未排查；本方向另有 rabin2 / checksec 可用',
    },
    // ── 密码学 / TLS ──
    {
        id: 'sslyze',
        direction: 'crypto',
        kind: 'cli',
        command: ['sslyze'],
        capability: 'TLS 配置审计：废弃协议、Heartbleed、ROBOT、CCS 注入、压缩与重协商，JSON 输出',
        priority: 10,
        accepts: ['url', 'host'],
        cost: 'cheap',
        defaultTimeoutMs: 300_000,
        // sslyze 要 host:port 而不是 URL；给了 URL 就拆出主机，没给端口按 https 补 443。
        invocation: (target, ctx) => {
            let hostport = target.trim();
            if (/^https?:\/\//i.test(hostport)) {
                try {
                    const u = new URL(hostport);
                    hostport = u.port === '' ? `${u.hostname}:${u.protocol === 'https:' ? '443' : '80'}` : `${u.hostname}:${u.port}`;
                }
                catch {
                    /* 解析失败就按原样交给 sslyze，让它自己报错 */
                }
            }
            else if (/^[^/:]+$/.test(hostport)) {
                hostport = `${hostport}:443`;
            }
            return [`--json_out=${path.join(ctx.evidenceDir, 'sslyze.json')}`, '--quiet', hostport];
        },
        verdict: sslyzeVerdict,
    },
    {
        id: 'rsacrack',
        direction: 'crypto',
        kind: 'cli',
        // 75 种攻击：wiener / boneh_durfee / fermat / hastads / common_modulus / lattice / z3_solver 等。
        // 装在 aisec venv 里（editable 安装自源码），入口有两个别名。
        command: ['/root/proj/agents/venvs/aisec/bin/RsaCtfTool'],
        capability: 'RSA 全攻击面：小 e、共模、Håstad 广播、Wiener 连分数、Boneh-Durfee、Fermat 分解、格攻击',
        priority: 10,
        accepts: ['file'],
        cost: 'moderate',
        defaultTimeoutMs: 300_000,
        // ⚠️ 不要加 `--attack all`：那条路会走 factordb 联网查询，外网受限时长时间重试到超时。
        // 实测默认攻击集对 128 位 n 秒级恢复出私钥（rc=0，两个 PEM 块），已经够用。
        invocation: (target) => ['--publickey', target, '--private', '--timeout', '120'],
        verdict: rsaVerdict,
        requires: '吃的是公钥文件（PEM/DER）；纯 n/e/c 数值要用 --n/--e 传参，别用 --e（和 --ext 有歧义）',
    },
    // ── 内网 / AD ──
    {
        id: 'enum4linux-ng',
        direction: 'internal-ad',
        kind: 'cli',
        command: ['enum4linux-ng'],
        capability: 'SMB/RPC 无凭据枚举：空会话、guest 登录、共享与用户列表，JSON 报告',
        priority: 10,
        accepts: ['host'],
        cost: 'cheap',
        defaultTimeoutMs: 300_000,
        // -oJ 会自动追加 .json，所以这里给不带后缀的路径，verdict 读 enum4linux.json。
        invocation: (target, ctx) => ['-A', '-oJ', path.join(ctx.evidenceDir, 'enum4linux'), target],
        verdict: enum4linuxVerdict,
    },
    // ── Web 渗透 ──
    {
        id: 'nuclei',
        direction: 'web-pentest',
        kind: 'cli',
        command: ['nuclei'],
        capability: '模板化 Web 漏洞扫描：CVE / 暴露面 / 错误配置，每行一个 JSON 命中。' +
            '默认只跑 high/critical（本机实测：4532 模板 / 约 75s）。全量 11315 模板对单目标约 430s，' +
            '而 medium/info 档里大量是版本匹配型模板，误报率高且与 whatweb/httpx 的指纹产出重叠——' +
            '**这两个档位本 agent 不覆盖**，需要时另跑，别把「没命中」当成「不存在」。',
        priority: 10,
        accepts: ['url', 'host'],
        cost: 'moderate',
        // 75s 实测 + 目标响应慢时的余量。原来 900s 是按全量模板设的，与默认的 severity 收窄不自洽。
        defaultTimeoutMs: 300_000,
        invocation: (target) => ['-u', target, '-jsonl', '-silent', '-nc', '-duc', '-severity', 'high,critical'],
        verdict: nucleiVerdict,
    },
    {
        id: 'cloud-bucket',
        direction: 'web-pentest',
        kind: 'cli',
        // 四家云的对象存储桶检测：阿里云 / 腾讯云 / 华为云 / AWS，含桶不存在时的劫持判定。
        // 装在 aisec venv 里（requirements.txt 锁了 cffi==1.15.1 在 3.13 上装不了，
        // 依赖是逐个补的）。
        command: ['/root/proj/agents/venvs/aisec/bin/python',
            '/root/proj/agents/Cloud-Bucket-Leak-Detection-Tools-main/main.py'],
        capability: '云存储桶暴露面：四家云的对象存储公开读/可写/桶名悬空（可劫持）判定',
        priority: 25,
        accepts: ['url', 'host'],
        cost: 'cheap',
        defaultTimeoutMs: 120_000,
        invocation: (target) => ['-aliyun', target],
        verdict: bucketVerdict,
        requires: '只做了阿里云入口；腾讯/华为/AWS 分别是 -tcloud / -hcloud / -aws。' +
            'config/conf.py 里的 AK 仅批量模式需要，单桶探测不需要',
    },
    {
        id: 'strix',
        direction: 'web-pentest',
        kind: 'cli',
        // 装在独立 venv 里，不在 PATH 上。和 semgrep 同一处理方式。
        command: ['/root/proj/agents/.venv/bin/strix'],
        capability: '多 agent 协同黑盒 Web/API 测试，生成可复现 PoC 与修复补丁',
        priority: 20,
        accepts: ['url', 'directory', 'file', 'host'],
        cost: 'expensive',
        defaultTimeoutMs: 1_800_000,
        // 它把结果写进 ./strix_runs，必须在自己的目录里跑，否则并发派活互相覆盖。
        ownWorkdir: true,
        // 沙箱 + LLM 双依赖，跑一次有真实花费。收窄轮次与预算，避免一次派活烧穿额度。
        invocation: (target, ctx) => {
            const cfg = writeStrixConfig(ctx.evidenceDir);
            return ['-t', target, '-n', '--fail-on', 'high', '--max-turns', '80', '--max-budget', '2', '--config', cfg];
        },
        verdict: strixVerdict,
        requires: '需要 docker 与沙箱镜像（默认从 ghcr.nju.edu.cn 取，直连 ghcr.io 拉不动）；' +
            '目标若是 127.0.0.1 需容器能回连宿主，否则容器内不可达',
        requiresEnv: [['LLM_API_KEY', 'OPENAI_API_KEY']],
    },
    // ── Pwn：从「看懂」走到「打穿」 ──
    //
    // 这个方向和 binary-reverse 的分工是刻意的：逆向关心「这是什么、怎么运行」，
    // 利用关心「控制流能不能被夺走」。原来 registry 里只有 checksec/radare2 这类
    // 静态分析，缺的正是最后一段——构造利用需要 gadget 清单和一次性 getshell 偏移。
    {
        id: 'ropgadget',
        direction: 'pwn',
        kind: 'cli',
        command: ['ROPgadget'],
        capability: 'ROP gadget 清单：控制寄存器、syscall、栈迁移片段，构造 ROP 链的原材料',
        priority: 10,
        accepts: ['binary', 'file'],
        cost: 'cheap',
        defaultTimeoutMs: 120_000,
        invocation: (target) => ['--binary', target],
        verdict: gadgetVerdict,
        // 不设 control：任何二进制都有 gadget，没有"clean"形态可供校准。
        // gadgetVerdict 因此只把它记成 exposure，绝不报 finding。
    },
    {
        id: 'one-gadget',
        direction: 'pwn',
        kind: 'cli',
        command: ['one_gadget'],
        capability: 'libc 里满足约束的一次性 execve("/bin/sh") 偏移，省掉整条 ROP 链',
        priority: 15,
        accepts: ['binary', 'file'],
        cost: 'moderate',
        defaultTimeoutMs: 120_000,
        invocation: (target) => ['-l', '2', target],
        verdict: gadgetVerdict,
    },
    // ── Misc：隐写与文件雕刻 ──
    //
    // 这一类没有共同方法论，共同点只是「都不需要靶机实例」。
    // 两条判据都刻意收紧到只认确凿证据：宁可 inconclusive，不猜 found。
    {
        id: 'binwalk',
        direction: 'misc',
        kind: 'cli',
        command: ['binwalk'],
        capability: '文件签名雕刻：找出容器里的嵌入文件、压缩流、固件段',
        priority: 10,
        accepts: ['file', 'binary'],
        cost: 'cheap',
        defaultTimeoutMs: 180_000,
        invocation: (target) => [target],
        verdict: carveVerdict,
        control: {
            argv: ['binwalk', '$TARGET'],
            target: '/root/异构agent/dsh-secops/tools/control-clean.png',
            expect: 'clean',
            note: '一张 64x64 纯渐变 PNG 只有自身签名（PNG image）。若它报出第二个签名，' +
                '说明签名库或参数把容器头误当嵌入内容，此时任何"发现"都不可信。',
        },
    },
    {
        id: 'zsteg',
        direction: 'misc',
        kind: 'cli',
        command: ['zsteg'],
        capability: 'PNG/BMP 位平面扫描：逐通道逐位提取嵌入的文本或完整文件',
        priority: 12,
        accepts: ['file'],
        cost: 'cheap',
        defaultTimeoutMs: 90_000,
        invocation: (target) => ['-a', target],
        verdict: stegoVerdict,
        // ⚠️ 不设 control：实测它连一张干净渐变图都会吐出二十多条 text: 行
        //（"U" repeated 64 times 这类规律填充），并不存在"输出干净"的样本可比。
        // 判据因此只认 file: 且排除它自己会误认的容器类型，其余一律 inconclusive。
    },
    {
        id: 'steghide',
        direction: 'misc',
        kind: 'cli',
        command: ['steghide'],
        capability: 'JPEG/BMP/WAV 隐写探测与提取（空口令 + 常见口令清单）',
        priority: 20,
        accepts: ['file'],
        cost: 'cheap',
        defaultTimeoutMs: 60_000,
        invocation: (target) => ['info', '-sf', target, '-p', ''],
        verdict: stegoVerdict,
        requires: 'JPEG/BMP/WAV 才适用（PNG 不支持），遇到 PNG 会自动 inconclusive',
    },
];
