/**
 * 检测器对照：用一个已知结论的样本证明「工具本身没坏」。
 *
 * 解决的问题不是「目标安不安全」，而是「我这把尺子准不准」。
 *
 * web 漏洞有天然对照：越权读到数据之后，用正常参数再打一次，看正常请求
 * 返回什么。二进制加固检查没有这个对照——你没法让同一个二进制「加固着」
 * 再跑一遍。TLS 配置同理。这类方向上唯一的验证手段是**校准尺子**：
 * 拿一个已知加固齐全的样本（发行版打包的 /usr/bin/ls）跑同一条命令，
 * 它必须报 clean。它要是也报缺 canary，那问题在工具或环境，不在目标。
 *
 * 三种结果必须分开，因为处理方式完全不同：
 *   trusted    —— 对照样本报 clean，工具可信，它对目标的结论可以用
 *   untrusted  —— 对照样本也报问题，工具不可用，它对目标的一切结论作废
 *   error      —— 跑不起来（没装/超时/崩了），既不能信也不能当作「目标正常」
 *
 * untrusted 和 error 都不能当成「目标清洁」——这是最容易被写错的地方：
 * 检测失败被读成「没发现问题」，最后报告里一条漏洞都没有还被当成好结果。
 */
import { spawn } from 'node:child_process';
/** 从任意输出里抽出「加固项 → 值」的表。 */
export function extractProtections(stdout) {
    const out = new Map();
    const text = stdout.trim();
    if (text.startsWith('{')) {
        try {
            const parsed = JSON.parse(text);
            // checksec 的 JSON 是 { "/path": {...} }，只有一层；展平最内层对象。
            const flatten = (value) => {
                if (value === null || typeof value !== 'object')
                    return;
                for (const [k, v] of Object.entries(value)) {
                    if (v !== null && typeof v === 'object')
                        flatten(v);
                    else
                        out.set(k.toLowerCase(), String(v).toLowerCase());
                }
            };
            flatten(parsed);
            return out;
        }
        catch {
            /* 不是合法 JSON，退回按行解析 */
        }
    }
    for (const line of text.split('\n')) {
        const m = /^\s*([A-Za-z0-9_.-]+)\s+(.+?)\s*$/.exec(line);
        if (m?.[1] !== undefined && m[2] !== undefined)
            out.set(m[1].toLowerCase(), m[2].toLowerCase());
    }
    return out;
}
/**
 * 已知加固样本应当给出的判定。
 *
 * 只覆盖「有确定正面值」的项。缺项**不算失败**：rabin2 压根不报 pie/relro，
 * 拿缺项判失败会把所有非 checksec 工具全判成不可信。
 * 但出现的项必须是正面值——那是这个样本的已知事实，不是对目标的期望。
 */
const EXPECTED_CLEAN = [
    { key: 'canary', ok: ['yes', 'true', 'found'] },
    { key: 'nx', ok: ['yes', 'true'] },
    { key: 'pie', ok: ['yes', 'true'] },
    { key: 'relro', ok: ['full'] },
    { key: 'fortify_source', ok: ['yes', 'true'] },
];
/**
 * 判定一次对照输出是否「报 clean」。
 *
 * 一个加固项都没解析出来也判不 clean：输出格式变了、工具换了版本，
 * 都意味着这条判定链断了，此时「没报问题」和「没法判断」是同一件事。
 */
export function judgeControl(stdout) {
    const table = extractProtections(stdout);
    const seen = [];
    const bad = [];
    for (const { key, ok } of EXPECTED_CLEAN) {
        const value = table.get(key);
        if (value === undefined)
            continue;
        seen.push(`${key}=${value}`);
        if (!ok.includes(value))
            bad.push(`${key}=${value}`);
    }
    if (seen.length === 0) {
        const head = stdout.trim().split('\n').slice(0, 2).join(' / ');
        return {
            clean: false,
            observed: 'no-protection-field',
            reason: `对照输出里解析不到任何加固项，无法判定检测器是否可信（输出开头：${head.slice(0, 120)}）`,
        };
    }
    const observed = seen.join(' ');
    if (bad.length > 0) {
        return {
            clean: false,
            observed,
            reason: `对照样本本应加固齐全，实际 ${bad.join(' ')} — 检测器或环境有问题，它对目标的结论不能用`,
        };
    }
    return { clean: true, observed, reason: `对照样本加固齐全（${observed}），检测器可信` };
}
/** 带超时执行一条命令，收集输出。不抛异常——失败也是一种结果。 */
function runCommand(argv, timeoutMs) {
    return new Promise((resolve) => {
        const [bin, ...rest] = argv;
        if (bin === undefined) {
            resolve({ code: null, stdout: '', stderr: 'empty argv' });
            return;
        }
        let stdout = '';
        let stderr = '';
        let settled = false;
        const child = spawn(bin, rest, { stdio: ['ignore', 'pipe', 'pipe'] });
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            child.kill('SIGKILL');
            resolve({ code: null, stdout, stderr: `${stderr}\n[control-check] timeout after ${String(timeoutMs)}ms` });
        }, timeoutMs);
        child.stdout.on('data', (chunk) => {
            stdout += chunk.toString('utf8');
        });
        child.stderr.on('data', (chunk) => {
            stderr += chunk.toString('utf8');
        });
        child.on('error', (err) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve({ code: null, stdout, stderr: `${stderr}\n${err.message}` });
        });
        child.on('close', (code) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve({ code, stdout, stderr });
        });
    });
}
/** 对单个候选跑对照。没声明 control 的候选直接返回 undefined。 */
export async function runControl(candidate, options = {}) {
    const control = candidate.control;
    if (control === undefined)
        return undefined;
    const argv = control.argv.map((a) => a.replace('$TARGET', control.target));
    const startedAt = Date.now();
    const { code, stdout, stderr } = await runCommand(argv, options.timeoutMs ?? 30_000);
    const durationMs = Date.now() - startedAt;
    const base = { agentId: candidate.id, target: control.target, argv, exitCode: code, durationMs };
    if (code !== 0) {
        return {
            ...base,
            verdict: 'error',
            observed: `exit=${String(code)}`,
            reason: `对照命令没跑成：${stderr.trim().split('\n').slice(-2).join(' / ').slice(0, 200) || '无输出'}`,
        };
    }
    const judged = judgeControl(stdout);
    return {
        ...base,
        verdict: judged.clean ? 'trusted' : 'untrusted',
        observed: judged.observed,
        reason: judged.reason,
    };
}
/**
 * 跑所有声明了 control 的候选。
 *
 * 并行跑：这些是本地单文件检查，各几百毫秒，串行纯属浪费。
 */
export async function runAllControls(registry, options = {}) {
    const candidates = registry.all().filter((c) => {
        if (c.control === undefined)
            return false;
        return options.only === undefined || options.only.includes(c.id);
    });
    const runs = await Promise.all(candidates.map((c) => runControl(c, options)));
    return runs.filter((r) => r !== undefined);
}
/** 对照结果的进程内账本。按 agentId 记最近一次，供 claim 侧查询。 */
export class ControlLedger {
    latest = new Map();
    record(run) {
        this.latest.set(run.agentId, run);
    }
    recordAll(runs) {
        for (const run of runs)
            this.record(run);
    }
    get(agentId) {
        return this.latest.get(agentId);
    }
    /**
     * 某个工具在目标上得出的结论能不能采信。
     *
     * 没跑过对照 → false。这里刻意选择「未校准即不可信」而不是「未校准按乐观处理」：
     * 二进制加固类的结论一旦虚报，下游会按「目标无防护」规划攻击路径，
     * 代价远高于多跑一次几百毫秒的本地检查。
     */
    isTrusted(agentId) {
        return this.latest.get(agentId)?.verdict === 'trusted';
    }
    /** 所有 untrusted/error 的对照，用来在报告里说明「这些结论为什么不能用」。 */
    problems() {
        return [...this.latest.values()].filter((r) => r.verdict !== 'trusted');
    }
    all() {
        return [...this.latest.values()];
    }
}
/**
 * 把账本变成 ClaimStore 的校准准入判定。
 *
 * 检三件事，缺一不可：
 *   1. ref 是 detector_check 造的那种引用串，而不是模型自己编的
 *   2. 账本里真有这个工具的记录（跑过才算）
 *   3. 记录是 trusted（工具在已知样本上判对了）
 *
 * 第 3 条是关键：检测器在已知加固样本上都说「缺防护」，那它对目标的
 * 「缺防护」结论就是它的毛病，不是目标的。这种输出进报告，比没有输出更糟。
 */
export function controlGateOf(ledger) {
    return (ref) => {
        const m = /^control:([^@]+)@([^:]+):/.exec(ref);
        if (m?.[1] === undefined || m[2] === undefined) {
            return {
                ok: false,
                reason: 'role=control 的 ref 必须原样使用 detector_check 返回的 ref（形如 control:<agent>@trusted:...）。' +
                    '自己编的校准声明无法核对——它一旦被接受，任何断言都能凭空升到 calibrated。',
            };
        }
        const agentId = m[1];
        const claimed = m[2];
        const run = ledger.get(agentId);
        if (run === undefined) {
            return { ok: false, reason: `账本里没有 ${agentId} 的校准记录——先跑 detector_check，再附这条证据。` };
        }
        if (run.verdict !== 'trusted') {
            return {
                ok: false,
                reason: `${agentId} 在已知加固样本上的判定是 ${run.verdict}（${run.observed}）：${run.reason} ` +
                    '这个检测器对目标的结论不能采信，换成同方向的其他候选或别的检测方法。',
            };
        }
        if (claimed !== run.verdict) {
            return { ok: false, reason: `ref 声称 ${claimed}，账本记录是 ${run.verdict}——以账本为准。` };
        }
        return { ok: true };
    };
}
